OpenWrt packaging plan for IPTV
===============================

This directory contains feed-style package definitions for OpenWrt 25.12+.

Design goals
------------

- Keep the OpenWrt integration UCI-native: LuCI edits `/etc/config/iptv`.
- Keep the Rust daemon portable: the init script renders UCI into the existing
  TOML format at `/var/etc/iptv.toml` before starting the service.
- Use `procd` for lifecycle, logging, respawn, and UCI reload triggers.
- Keep the web UI as a modern LuCI JavaScript app with `menu.d` and `rpcd`
  ACL declarations.
- Install prebuilt musl release binaries so SDK builds do not need to build
  Rust, rustc, or LLVM.

Package layout
--------------

- `iptv/`: daemon binary package, default UCI config, and procd init script.
- `luci-app-iptv/`: LuCI UI package depending on the daemon package.
- `configs/`: OpenWrt build `.config` files for different branches or devices.

Expected feed usage
-------------------

From an OpenWrt source tree or SDK, copy the package directories into the local
package tree:

```sh
cd openwrt

mkdir -p package/iptv
cp -a ~/iptv-rs/openwrt/iptv package/iptv/
cp -a ~/iptv-rs/openwrt/luci-app-iptv package/iptv/
```

Update feeds, select packages, then compile:

```sh
./scripts/feeds update -a
./scripts/feeds install iptv luci-app-iptv
make menuconfig
make package/iptv/compile package/luci-app-iptv/compile
```

Before publishing packages, set `PKG_SOURCE_URL` and `PKG_HASH` in
`iptv/Makefile` to immutable release assets. The current package supports
prebuilt `aarch64-unknown-linux-musl` and `x86_64-unknown-linux-musl` assets
from the upstream GitHub release.

GitHub Actions firmware builds
------------------------------

The `OpenWrt Snapshot` workflow can build firmware from OpenWrt source and a
stored `.config` file. The default config is:

```text
openwrt/configs/mediatek-filogic-snapshot.config
```

For release branches, add a branch-specific config next to it, for example:

```text
openwrt/configs/mediatek-filogic-24.10.config
openwrt/configs/mediatek-filogic-25.12.config
```

For a fixed OpenWrt release tag, use a tag-specific config name, for example:

```text
openwrt/configs/mediatek-filogic-v25.12.4.config
```

When running the workflow manually, set:

```text
openwrt_ref = master
config_file = openwrt/configs/mediatek-filogic-snapshot.config
```

or, for a release branch:

```text
openwrt_ref = openwrt-25.12
config_file = openwrt/configs/mediatek-filogic-25.12.config
```

or, for a fixed release tag:

```text
openwrt_ref = v25.12.4
config_file = openwrt/configs/mediatek-filogic-v25.12.4.config
```
