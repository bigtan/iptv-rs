# iptv-rs

简体中文 | [English](README_en.md)

`iptv-rs` 是一个使用 Rust 编写的、独立维护的 IPTV 代理服务。

它提供：
- 播放列表（M3U）与 XMLTV 节目单聚合
- UDP 组播代理
- 针对 `/udp/...?...` 直播流的电信 FCC 快速切台引导支持
- 基于原生 Rust RTSP 客户端的 RTSP 回看/时移与直播代理
- 频道别名、分组与画质优选规则
- 轻量级管理端点

## 许可证

- 本项目基于 `AGPL-3.0-only` 开源。详见 [LICENSE](LICENSE)。
- 第三方归属说明见 [NOTICE](NOTICE) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- 保留的第三方许可证原文存放在 [licenses/](licenses)。

## 使用方法

```text
Usage: iptv-rs [OPTIONS] --user <USER> --passwd <PASSWD> --mac <MAC>

Options:
  -u, --user <USER>                      Login username (or config [app].user)
  -p, --passwd <PASSWD>                  Login password (or config [app].passwd)
  -m, --mac <MAC>                        MAC address (or config [app].mac)
  -i, --imei <IMEI>                      IMEI (or config [app].imei) [default: ]
  -b, --bind <BIND>                      Bind address:port (or config [app].bind) [default: 0.0.0.0:7878]
  -a, --address <ADDRESS>                IP address/interface name (or config [app].address) [default: ]
  -I, --interface <INTERFACE>            Interface to request (or config [app].interface)
  -c, --config <CONFIG>                  Config file path (TOML)
      --extra-playlist <EXTRA_PLAYLIST>  Url to extra m3u
      --extra-xmltv <EXTRA_XMLTV>        Url to extra xmltv
      --udp-proxy                        Use UDP proxy
      --rtsp-proxy                       Use rtsp proxy
  -h, --help                             Print help
```

## 配置

大多数运行选项都可以配置在 TOML 配置文件中，并通过 `-c` 参数加载。

示例文件：
- [config/iptv.toml](config/iptv.toml)

主要配置节：
- `[app]`: 登录信息、监听地址、代理开关
- `[auth]`: Token 鉴权保护配置，支持可选的 `rtsp`、`udp` 和 `logo` 保护
- `[fcc]`: FCC 功能开启与超时参数调优
  基于 RTP 序列号平滑切换至组播，并在切换前保持单播播放最小等待时间。
- `[alias]`: 频道别名重写规则
- `[resolution]`: 画质评分与优选规则
- `[groups]`: 频道分组
- `[template]`: 播放列表渲染模板
- `[xmltv]`: XMLTV 命名行为
- `[manage]`: 管理端点开启控制

## 接口端点

- `/playlist`
- `/xmltv`
- `/status`
- `/manage`
- `/manage/config`
- `/manage/reload`
- `/manage/test?name=...`
- `/manage/channels`
- `/manage/channels/html`
- `/udp/{addr}?fcc=ip:port`
- `/rtp/{addr}?fcc=ip:port`
- `/rtsp/{tail:.*}`

## 鉴权认证

如果配置了 `auth.token` 且目标端点开启了保护，可以通过以下方式传入 Token：

- `Authorization: Bearer <TOKEN>`
- `X-Api-Token: <TOKEN>`
- `?token=<TOKEN>`

当启用了对 `rtsp`、`udp` 或 `logo` 的保护时，生成的播放列表 URL 将自动携带配置的 Token。在将 RTSP 请求向上游转发之前，本地 Token 会被自动移除。

`/rtsp` 与 `/udp` 路由仅在开启对应的代理开关时可用。这些代理端点设计用于可信局域网；如果需要暴露在更广泛的网络环境中，请务必使用认证 Token 进行保护。

上游成功的鉴权授权状态每 6 小时刷新一次。在打开流之前，若上一次成功鉴权已超过 8 小时，服务也会自动刷新授权。当 RTSP 响应 401/403 时，会触发一次强制刷新并无感重试 SETUP。

管理页面内置了样式表，无需外网连接即可正常访问。

## 编译构建

本机编译：

```bash
cargo build --release
```

Release 构建针对媒体转发热路径进行了吞吐量优化。如果相较于 CPU 占用更看重二进制体积，可以使用 `cargo build --profile release-small`。

交叉编译：

```bash
cargo install cargo-cross
cargo cross build --release --target x86_64-unknown-linux-musl
```

TLS 特性选择：

- 默认启用 Rustls，以便在 release 构建中支持通过 HTTPS 获取额外的播放列表与 XMLTV
- `--no-default-features --features tls` 使用系统原生 TLS / OpenSSL
- `--no-default-features` 构建仅支持 HTTP 的极简版本

## OpenWrt 支持

本项目提供了面向 OpenWrt 的完整集成支持，定义文件位于 [openwrt/](openwrt) 目录：

- `iptv`：核心守护进程包，包含预编译 musl 静态二进制程序、procd init 服务脚本及 UCI 默认配置文件。
- `luci-app-iptv`：原生的 LuCI Web 图形管理界面。

### 服务管理与 UCI 配置

服务生命周期由 OpenWrt 的 `procd` 进行托管，配置项保存在 `/etc/config/iptv`。服务启动时，init 脚本会自动将 UCI 配置转换为 `/var/etc/iptv.toml` 并拉起进程。

基本服务管理命令：

```sh
# 启用开机自启并启动服务
/etc/init.d/iptv enable
/etc/init.d/iptv start

# 检查运行状态或重新加载配置
/etc/init.d/iptv status
/etc/init.d/iptv reload
```

通过 UCI 命令行配置示例：

```sh
uci set iptv.main.enabled='1'
uci set iptv.main.user='YOUR_USER'
uci set iptv.main.passwd='YOUR_PASSWORD'
uci set iptv.main.mac='YOUR_MAC'
uci set iptv.main.interface='pppoe-iptv'
uci commit iptv
/etc/init.d/iptv restart
```

### 编译与固件构建

可将项目中的 package 目录复制到 OpenWrt 源码树或 SDK 中进行编译，亦可通过 GitHub Actions 自动化构建固件。详细构建步骤与配置参见 [openwrt/README.md](openwrt/README.md)。
