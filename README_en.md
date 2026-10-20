# iptv-rs

English | [简体中文](README.md)

`iptv-rs` is an independently maintained IPTV proxy written in Rust.

It provides:
- playlist and XMLTV aggregation
- UDP multicast proxying
- Telecom FCC bootstrap for `/udp/...?...` streams
- RTSP replay/live proxying with a native Rust RTSP client
- alias/group/resolution rules
- lightweight management endpoints

## License

- This project is licensed under `AGPL-3.0-only`. See [LICENSE](LICENSE).
- Third-party attribution is documented in [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Retained third-party license texts are stored in [licenses/](licenses).

## Usage

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

## Configuration

Most runtime options can be placed into a TOML config file and loaded with `-c`.

Example file:
- [config/iptv.toml](config/iptv.toml)

Key sections:
- `[app]`: login, bind address, proxy switches
- `[auth]`: token protection, including optional `rtsp`, `udp`, and `logo` protection
- `[fcc]`: FCC enablement and timeout tuning
  Uses RTP sequence numbers for multicast switchover, with a minimum unicast play time before switching.
- `[alias]`: alias rewrite rules
- `[resolution]`: quality scoring rules
- `[groups]`: channel grouping
- `[template]`: playlist rendering templates
- `[xmltv]`: XMLTV naming behavior
- `[manage]`: management endpoint enablement

## Endpoints

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

## Authentication

If `auth.token` is configured and an endpoint is protected, you can pass the token by:

- `Authorization: Bearer <TOKEN>`
- `X-Api-Token: <TOKEN>`
- `?token=<TOKEN>`

When `rtsp`, `udp`, or `logo` is protected, generated playlist URLs carry the
configured token automatically. The local token is removed before an RTSP
request is forwarded upstream.

The `/rtsp` and `/udp` routes are available only when their corresponding
proxy switch is enabled. These proxy endpoints are intended for trusted LANs;
protect them with an authentication token if they are exposed more broadly.

Successful upstream authorization is refreshed every six hours. Before opening
a stream, the service also refreshes authorization when the last success is
older than eight hours. An RTSP 401/403 response triggers one forced refresh and
one transparent setup retry.

Management pages embed their stylesheet and do not require Internet access.

## Build

Native build:

```bash
cargo build --release
```

Release builds optimize the media forwarding hot path for throughput. If binary
size matters more than CPU usage, use `cargo build --profile release-small`.

Cross build:

```bash
cargo install cargo-cross
cargo cross build --release --target x86_64-unknown-linux-musl
```

TLS feature selection:

- Rustls is enabled by default so HTTPS extra playlists/XMLTV work in release builds
- `--no-default-features --features tls` for native TLS/OpenSSL
- `--no-default-features` for an HTTP-only minimal build

## OpenWrt Integration

This repository provides native OpenWrt package definitions under [openwrt/](openwrt):

- `iptv`: Daemon package containing prebuilt musl release binaries, a procd init script, and default UCI configuration.
- `luci-app-iptv`: Modern LuCI Web UI application for graphical configuration.

### Service Management and UCI Configuration

Service lifecycle is managed by OpenWrt's `procd`. Configuration is stored in `/etc/config/iptv`. Upon starting, the init script renders UCI settings into `/var/etc/iptv.toml` before launching the daemon.

Common service commands:

```sh
# Enable at startup and start the service
/etc/init.d/iptv enable
/etc/init.d/iptv start

# Check status or reload configuration
/etc/init.d/iptv status
/etc/init.d/iptv reload
```

Example configuration via UCI CLI:

```sh
uci set iptv.main.enabled='1'
uci set iptv.main.user='YOUR_USER'
uci set iptv.main.passwd='YOUR_PASSWORD'
uci set iptv.main.mac='YOUR_MAC'
uci set iptv.main.interface='pppoe-iptv'
uci commit iptv
/etc/init.d/iptv restart
```

### Building and Feed Integration

Package directories can be copied into an OpenWrt source tree or SDK for compilation, or built via GitHub Actions workflows. See [openwrt/README.md](openwrt/README.md) for full build instructions and feed details.
