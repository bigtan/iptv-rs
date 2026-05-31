include $(TOPDIR)/rules.mk

PKG_NAME:=iptv-rs
PKG_VERSION:=0.3.1
PKG_RELEASE:=1

PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/bigtan/iptv-rs/archive/refs/tags
PKG_HASH:=8f654af2d41fb6d5cd02a8915788c81b2894681989798b5556545cea19f5e592
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=iptv-rs maintainers

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/iptv-rs
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Rust IPTV proxy with RTSP replay and multicast proxy support
  URL:=https://github.com/bigtan/iptv-rs
  DEPENDS:=$(RUST_ARCH_DEPENDS) +ca-bundle
endef

define Package/iptv-rs/description
  iptv-rs is an IPTV proxy with playlist/XMLTV aggregation, UDP multicast
  proxying, Telecom FCC bootstrap support, RTSP replay, and management
  endpoints.
endef

CARGO_PKG_FEATURES:=rustls

$(eval $(call RustBinPackage,iptv-rs))

define Package/iptv-rs/conffiles
/etc/config/iptv-rs
endef

define Package/iptv-rs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(CARGO_INSTALL_ROOT)/bin/iptv-rs $(1)/usr/bin/iptv-rs
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/iptv-rs.config $(1)/etc/config/iptv-rs
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/iptv-rs.init $(1)/etc/init.d/iptv-rs
endef

$(eval $(call BuildPackage,iptv-rs))
