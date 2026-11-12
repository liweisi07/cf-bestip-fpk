"""Run CloudflareSpeedTest and pick the best IP from its result.csv.

The tool itself (XIU2 CloudflareSpeedTest) is run with its default
behaviour: latency test first, then download speed test of the lowest
latency IPs, writing ``result.csv`` in the working directory. The result
file's first data row is already the tool's own "fastest" pick, but this
module re-ranks rows with an explicit, documented rule so the choice does
not depend on the tool's internal sort order:

    best = lowest packet loss, then lowest latency, then highest speed.

Only Python's standard library is used. The subprocess is started with
proxy environment variables stripped, because a proxy in the path would
make the measurement meaningless (the tool's own documentation warns that
an unexpectedly low latency means traffic went through a proxy).
"""

import csv
import os
import subprocess
import threading
import time

# Header names used by CloudflareSpeedTest's result.csv (XIU2, v2.x).
COL_IP = ("ip 地址", "ip")
COL_LOSS = ("丢包率",)
COL_LATENCY = ("平均延迟",)
COL_SPEED = ("下载速度(mb/s)",)


def _norm_header(name):
    return (name or "").strip().lower().replace(" ", "")


def _find_column(headers, wanted, fallback):
    normed = [_norm_header(h) for h in headers]
    for name in wanted:
        norm_name = _norm_header(name)
        if norm_name in normed:
            return normed.index(norm_name)
    return fallback


def parse_result_csv(path):
    """Parse a CloudflareSpeedTest result.csv into a list of rows.

    Each row is a dict with keys: ip, loss, latency, speed, region.
    Rows with an unparseable IP or non-numeric measurements are skipped.
    """
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        try:
            headers = next(reader)
        except StopIteration:
            return rows
        ci_ip = _find_column(headers, COL_IP, 0)
        ci_loss = _find_column(headers, COL_LOSS, 3)
        ci_lat = _find_column(headers, COL_LATENCY, 4)
        ci_speed = _find_column(headers, COL_SPEED, 5)
        for raw in reader:
            if not raw or len(raw) <= max(ci_ip, ci_loss, ci_lat, ci_speed):
                continue
            ip = raw[ci_ip].strip()
            if not ip:
                continue
            try:
                loss = float(raw[ci_loss])
                latency = float(raw[ci_lat])
                speed = float(raw[ci_speed])
            except (ValueError, TypeError):
                continue
            rows.append({
                "ip": ip,
                "loss": loss,
                "latency": latency,
                "speed": speed,
                "region": raw[6].strip() if len(raw) > 6 else "",
            })
    return rows


def rank_rows(rows):
    """Rows sorted best-first.

    A row whose download-speed test produced 0 proved nothing about
    real throughput (the probe answered, but no download completed),
    so it always ranks below any row with a measured speed, whatever
    its latency says. When every row has speed 0 the old ordering
    still applies, so a run never fails just for that.
    """
    return sorted(
        rows,
        key=lambda r: (0 if r["speed"] > 0 else 1,
                       r["loss"], r["latency"], -r["speed"]))


def top_rows(rows, count=10, region="all"):
    """The best `count` rows in ranked order.

    With a specific region, only that region's rows are shown; when
    the region has no rows, the global top rows are shown instead
    (the caller reports the fallback).
    """
    code = (region or "").strip().upper()
    if code and code != "ALL":
        candidates = rows_in_region(rows, code)
        if candidates:
            return rank_rows(candidates)[:count]
    return rank_rows(rows)[:count]


def rows_in_region(rows, region):
    """Rows whose region code matches `region` (case-insensitive).

    The region column comes from cfst's download test: it is the
    Cloudflare colo code taken from the response's cf-ray header
    (e.g. HKG, SIN, LAX). Rows that never went through the download
    test have an empty region and never match a specific region.
    """
    code = (region or "").strip().upper()
    if not code:
        return []
    return [r for r in rows
            if (r.get("region") or "").strip().upper() == code]


def pick_best(rows):
    """Return the best IP, or None when there is no usable row."""
    ordered = rank_rows(rows)
    return ordered[0]["ip"] if ordered else None


def pick_best_for_region(rows, region="all"):
    """Best IP inside `region`, with fallback to the global best.

    Returns (best_ip, fell_back): fell_back is True only when a
    specific region was asked for but no usable row carried that
    region code. "all" (or an empty region) means the old behaviour:
    the global best, never a fallback.
    """
    code = (region or "").strip().upper()
    if code and code != "ALL":
        candidates = rows_in_region(rows, code)
        if candidates:
            return pick_best(candidates), False
        return pick_best(rows), True
    return pick_best(rows), False


def _clean_env():
    """Environment without proxy variables, so the test is direct."""
    env = dict(os.environ)
    for key in list(env):
        if key.lower().endswith("_proxy"):
            env.pop(key, None)
    env["NO_PROXY"] = "*"
    return env


def run_speedtest(cfst_bin, ip_file, workdir, timeout=1800, on_line=None,
                  region="all"):
    """Run cfst in workdir.

    Returns (best_ip, log_text, top_rows, total_rows, fell_back):
    the best IP, the tool's raw output, the best 10 measured rows
    (ip/loss/latency/speed/region) for display, how many usable rows
    result.csv held, and whether a requested region had no rows so
    the global best was used instead.

    Raises RuntimeError with a readable message when the tool is missing,
    fails, times out, or produces no usable result.
    """
    if not os.path.isfile(cfst_bin):
        raise RuntimeError("测速程序不存在：%s" % cfst_bin)
    if not os.access(cfst_bin, os.X_OK):
        try:
            os.chmod(cfst_bin, 0o755)
        except OSError:
            pass
    os.makedirs(workdir, exist_ok=True)
    cmd = [cfst_bin, "-f", ip_file, "-o", "result.csv", "-p", "0"]
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            env=_clean_env(),
        )
    except OSError as exc:
        raise RuntimeError("无法启动测速程序：%s" % exc)
    # Stream the tool's own progress lines to the caller (the UI shows
    # them live) instead of waiting silently until the tool exits: a
    # 20-minute silent run looks exactly like a stuck run.
    log_parts = []

    def _reader():
        try:
            for raw in proc.stdout:
                # Split defensively on every line boundary: the tool
                # redraws progress with carriage returns, and a chunk
                # flushed at exit can hold several redraws at once.
                # Feeding them one by one is what lets the caller
                # collapse them into a single tidy progress line.
                for part in raw.splitlines():
                    line = part.strip()
                    if not line:
                        continue
                    log_parts.append(line)
                    if on_line:
                        try:
                            on_line(line)
                        except Exception:
                            pass
        except Exception:
            pass

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise RuntimeError("测速超时（超过 %d 秒），已停止" % timeout)
    # Drain the last buffered lines before using the log.
    reader.join(timeout=5)
    log = "\n".join(log_parts)
    if proc.returncode != 0:
        raise RuntimeError(
            "测速程序退出码 %d，输出尾部：%s"
            % (proc.returncode, log[-500:])
        )
    result_path = os.path.join(workdir, "result.csv")
    if not os.path.isfile(result_path):
        raise RuntimeError("测速完成但未生成 result.csv，输出尾部：%s" % log[-500:])
    rows = parse_result_csv(result_path)
    best, fell_back = pick_best_for_region(rows, region)
    if not best:
        raise RuntimeError("result.csv 中没有可用的测速结果")
    return best, log, top_rows(rows, region=region), len(rows), fell_back
