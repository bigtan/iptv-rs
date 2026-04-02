# iptv-rs

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
- `[auth]`: token protection
- `[fcc]`: FCC enablement and timeout tuning
  Includes startup buffering and delayed multicast switchover thresholds for high bitrate channels.
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

## Build

Native build:

```bash
cargo build --release
```

Cross build:

```bash
cargo install cargo-cross
cargo cross build --release --target x86_64-unknown-linux-musl
```

TLS feature selection:

- `--features rustls` for Rustls
- `--features tls` for native TLS/OpenSSL

## Service Example

```sh
#!/bin/sh /etc/rc.common

START=99
STOP=99

INTERFACE=pppoe-iptv
BIND=0.0.0.0:7878

start() {
    ( RUST_LOG=info /usr/bin/iptv-rs -c /etc/iptv/iptv.toml -b $BIND -I $INTERFACE --udp-proxy --rtsp-proxy 2>&1 & echo $! >&3 ) 3>/var/run/iptv-rs.pid | logger -t "iptv-rs" &
}

stop() {
    if [ -f /var/run/iptv-rs.pid ]; then
        kill -9 "$(cat /var/run/iptv-rs.pid)" 2>/dev/null
        rm -f /var/run/iptv-rs.pid
    fi
}
```
