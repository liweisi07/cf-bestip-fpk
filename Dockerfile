# CF优选IP（域名版）Docker 镜像：纯 Python 标准库，不需要额外依赖。
# 构建：docker build -t ghcr.io/liweisi07/cf-bestip-domain:1.0.22 .
# 运行：docker run -d --name cf-bestipd -p 18089:18089 -v ./data:/data ghcr.io/liweisi07/cf-bestip-domain:1.0.22
# 打开 http://NAS-IP:18089，默认账号 admin / 密码 admin，首次登录后请改掉。
FROM python:3.11-slim

WORKDIR /app

# 应用代码（含两个架构的 cfst 二进制，运行时按架构自动选用，
# 与 .fpk 包里的做法一致；首次运行不需要再下载）。
COPY app/ ./app/

# 数据目录（配置、订阅、测速结果）放 /data，用 volume 持久化，
# 删容器重建也不会丢配置。
ENV CFBESTIPD_DATA_DIR=/data

EXPOSE 18089

VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:18089/', timeout=5)"

CMD ["python3", "app/app.py"]
