OpenWrt packaging plan for iptv-rs
==================================

This directory contains feed-style package definitions for OpenWrt 25.12+.

Design goals
------------

- Keep the OpenWrt integration UCI-native: LuCI edits `/etc/config/iptv-rs`.
- Keep the Rust daemon portable: the init script renders UCI into the existing
  TOML format at `/var/etc/iptv-rs.toml` before starting the service.
- Use `procd` for lifecycle, logging, respawn, and UCI reload triggers.
- Keep the web UI as a modern LuCI JavaScript app with `menu.d` and `rpcd`
  ACL declarations.
- Install prebuilt musl release binaries so SDK builds do not need to build
  Rust, rustc, or LLVM.

Package layout
--------------

- `iptv-rs/`: daemon binary package, default UCI config, and procd init script.
- `luci-app-iptv-rs/`: LuCI UI package depending on the daemon package.

Expected feed usage
-------------------

From an OpenWrt source tree or SDK, copy the package directories into the local
package tree:

```sh
cd openwrt

mkdir -p package/iptv-rs
cp -a ~/iptv-rs/openwrt/iptv-rs package/iptv-rs/
cp -a ~/iptv-rs/openwrt/luci-app-iptv-rs package/iptv-rs/
```

Update feeds, select packages, then compile:

```sh
./scripts/feeds update -a
./scripts/feeds install iptv-rs luci-app-iptv-rs
make menuconfig
make package/iptv-rs/compile package/luci-app-iptv-rs/compile
```

Before publishing packages, set `PKG_SOURCE_URL` and `PKG_HASH` in
`iptv-rs/Makefile` to immutable release assets. The current package supports
prebuilt `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` assets
from the upstream GitHub release.
