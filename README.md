# CF 优选订阅（cf-bestip）

一个飞牛 fnOS 原生应用（无需 Docker）：定时测出最优 Cloudflare IP，
把 Sub-Store 订阅里走 Cloudflare 的节点地址换成最优 IP，客户端用 app
的订阅链接更新，拿到的就是优选 IP。

## 域名版（新增）

注：1.0.1 版修复了图标格式问题（改为 RGBA），解决应用中心“应用包不符合系统要求”安装被拒；仓库里只保留最新版：IP 版 1.0.6、域名版 1.0.9。

另外还有一个域名版：`cf-bestip-domain-1.0.9-arm64.fpk`（ARM64 专用，
默认端口 18089，可与 IP 版同时安装，互不干扰）。

- 节点地址不再写每次变化的最优 IP，而是写一个固定不变的域名
  （如 cf.997771.xyz）；最优 IP 每次测出来后，app 自动调 Cloudflare
  API 把这个域名的 DNS 记录指向最优 IP。
- 最优 IP 再变，客户端不用重新拉订阅，等 DNS 生效（TTL 60 秒）
  就自动连到新 IP。
- 记录固定写成“仅 DNS”（灰云，不开代理）：开了代理，解析出来的
  是任播 IP 而不是优选 IP；回查发现是代理状态会报错提醒。
- SNI 处理和 IP 版一样：原来有 servername/sni 的保留，空的填原域名，
  TLS 节点没有的补 servername=原域名。
- 需要在设置页“域名绑定”里填：Cloudflare API 令牌（用“Edit zone DNS”
  模板、只给这一个 Zone 的权限）、域名（Zone，如 997771.xyz，
  DNS 须托管在 Cloudflare）、记录名（如 cf）。令牌只存在 NAS 本机，
  页面和状态接口永远不会显示它。
- 安装后先点“立即更新 DNS 记录”看到成功，再把 app 链接换到客户端。
  DNS 更新失败不是致命错误：记录里留的是上一次的最优 IP，仍可正常用；
  域名绑定没配置时订阅原样输出，不会断网。

## 它是什么、不是什么

- **是**：Sub-Store 的“后处理层”。Sub-Store 仍负责转换订阅；本 app
  只在转换结果上改写走 CF 的节点地址，再提供新的订阅链接。
- **不是**：它不会改写 Sub-Store 自身保存的订阅，也不会刷新订阅内容。
  （Sub-Store 的 Cloudflare Workers 版没有能改节点地址的内置操作，
  脚本操作在该环境下也被禁用，所以改写只能放在 app 这一层做。）
- **链接不变、内容变**：app 的订阅链接是固定的；每次重新测速后，
  链接里的节点地址会更新成最新最优 IP。客户端需要再更新一次订阅
  才会拿到新 IP。

## 功能

1. **订阅管理**：内置 Web 设置页（局域网访问），添加/删除订阅。
   每条订阅就是一条 Sub-Store 下载链接（mihomo/ClashMeta YAML 格式），
   由你自己决定加哪些。
2. **定时测速**：用 CloudflareSpeedTest（XIU2 开源工具，linux_arm64
   版）定时测速，默认 7 天一次（可在设置页改，1–30 天）。
   最近一次的最优 IP 和测速时间会在设置页展示。
3. **改写逻辑**（核心）：
   - 拉取每条订阅的 mihomo YAML 输出。
   - 只改写“走 CF 的节点”：节点 server 原本是域名时，先解析该域名，
     只有解析出的 IPv4 属于 Cloudflare 官方 IPv4 段才认定为走 CF；
     server 本身已是 IP 字面量的节点一律不动；非 CF 域名不动。
   - 改写时把 server 换成最优 IP，并保证 TLS 不被破坏：原来有
     servername/sni 的原样保留；原来没有且节点走 TLS 的，补一个
     servername 等于原域名。
   - 其余内容逐字节保留（按行解析，只动 server 行和必要的
     servername 行，不重新序列化整个 YAML）。
   - Cloudflare 官方 IP 段内置了一份，并会在启动和手动触发时尝试从
     https://www.cloudflare.com/ips-v4 刷新，失败时用内置列表。
4. **订阅服务**：每条订阅一个稳定链接，如 `/sub/<名字>`，内容类型为
   YAML，可直接给 mihomo 客户端用；另有手动“立即测速并更新”按钮。
5. **运行方式**：FnOS 原生版，不依赖 Docker；纯 Python 3 标准库，
   无任何第三方 pip 依赖；内部定时循环，不依赖系统 cron 是否存在；
   默认端口 18088，可在安装向导里修改。

## 安装（飞牛应用中心手动安装）

1. 在飞牛桌面打开**应用中心 → 设置 → 手动安装应用**，选择
   `cf-bestip-1.0.4-arm64.fpk`（ARM64 设备专用，不要装到 x86 设备上）。
2. 安装向导里填服务端口（默认 `18088`，确保未被占用）和测速间隔
   （默认 `7` 天），完成安装，等应用中心显示“运行中”。
3. 在局域网内打开 `http://<NAS-IP>:18088`（或点应用图标），进入设置页。
4. 在“添加订阅”里填名字（只允许字母、数字、下划线、短横线）和
   Sub-Store 下载链接，例如名字填 `demo`，链接填
   `https://your-backend.example.com/YOUR_PREFIX/download/demo?target=ClashMeta&prettyYaml=true`
   （请换成你自己的真实链接；文档里的地址一律是占位符）。
5. 点**立即测速并更新**，等状态页显示最优 IP。
6. 把设置页里该订阅对应的 app 链接（形如
   `http://<NAS-IP>:18088/sub/demo`）复制到 mihomo 客户端当订阅链接用。

## 使用说明

- 以后每次想拿到最新优选 IP：等 app 定时测速（或手动点一次），
  再在客户端里更新一次订阅即可，链接不用换。
- 在 app 里增删订阅完全由你自己决定；删掉某条订阅后，它对应的
  app 链接也会失效。
- 桌面图标默认打开 18088 端口；如果你在向导里改了端口，请直接用
  `http://<NAS-IP>:新端口` 打开设置页。

## 安全提醒（请认真看）

- 本页面和订阅链接**只应在家里局域网内使用**：不要把本机端口映射
  到公网，不要把 app 的订阅链接外发给别人。
- app 不向任何第三方发送你的数据；它只访问：Cloudflare 测速目标、
  你自己填的 Sub-Store 链接、Cloudflare 官方 IP 段列表（可选刷新）。
- app 里保存的 Sub-Store 下载链接包含你的后端访问路径，请勿公开
  app 的配置文件和订阅链接。
- 测速时会产生测速流量（默认设置一次约几十到几百 MB），建议闲时
  跑；家用宽带、默认设置、低频跑一般不会被运营商限制。

## 常见问题

- **启动失败，日志说找不到 python3**：请先在飞牛应用中心安装
  Python 工具（或确认系统里有 python3），再启动本应用。
- **测速程序缺失且自动下载失败**：请检查 NAS 能否访问 github.com；
  也可以手动把 CloudflareSpeedTest 的 linux_arm64 版 `cfst` 程序放到
  应用数据目录的 `cfst-bin/` 下再重启应用。
- **某条订阅一直更新失败**：先在浏览器直接打开它的 Sub-Store 原链接，
  看原链接本身是否正常；原链接正常但 app 里失败时，看设置页的日志。
- **改写后客户端连不上**：先确认该节点原来就是走 CF 的域名节点；
  IP 字面量节点和非 CF 域名节点本应用不会动。如果某个 CF 节点在
  改写后异常，把它从 app 的订阅里单独排查（例如先看原链接是否正常）。

## 开发者说明

- 源码结构：`app/`（应用本体：`app.py` 设置页与订阅服务、
  `rewriter.py` 改写逻辑、`cfst.py` 测速运行与结果解析、
  `cf_ranges.txt` 内置 IP 段、`cfst` 测速程序 arm64 版、`ip.txt`
  测速用 IP 段文件、`ui/` 桌面入口）、`cmd/`（生命周期脚本）、
  `config/`（权限与资源声明）、`wizard/`（安装/设置向导）、
  `manifest`、`ICON.PNG`、`ICON_256.PNG`。
- 构建：`python3 scripts/build_fpk.py`，产物在 `dist/`；
  校验：`python3 scripts/verify_fpk.py dist/cf-bestip-1.0.4-arm64.fpk`。
- 测试：`python3 -m unittest discover -s tests`（改写逻辑、测速结果
  解析、服务端全流程）。
- 打包格式依据：飞牛 fnOS 官方开发者文档的 .fpk 契约（manifest、
  cmd、config、wizard、桌面入口），以及 Octop、fn-os-apps 等公开
  .fpk 项目的实际打包结构；本包未在真实飞牛设备上安装验证过，
  上架前请先在一台设备上手动安装验证。

## 许可与第三方组件

- 本应用代码：MIT License（见 LICENSE）。
- 内置测速工具 CloudflareSpeedTest：XIU2 开源项目，GPLv3，
  https://github.com/XIU2/CloudflareSpeedTest
