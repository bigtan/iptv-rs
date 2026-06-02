include $(TOPDIR)/rules.mk

PKG_NAME:=iptv
PKG_VERSION:=0.3.2
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/bigtan/iptv-rs/releases/download/v$(PKG_VERSION)

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=iptv-rs-aarch64-unknown-linux-musl.zip
  PKG_HASH:=7220e6f33f866be33be2c8517f197ce7135659f5a64a8a892b2b3f02a3433ebd
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=iptv-rs-x86_64-unknown-linux-musl.zip
  PKG_HASH:=1ffd69bc172a597e694fc84966b13e311771b5726b1b502d9361e6155f7175ab
else
  PKG_SOURCE:=unsupported-$(ARCH).zip
  PKG_HASH:=skip
endif

UNPACK_CMD=unzip -q -d $(PKG_BUILD_DIR) $(DL_DIR)/$(PKG_SOURCE)

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=iptv-rs maintainers

include $(INCLUDE_DIR)/package.mk

define Package/iptv
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Rust IPTV proxy with RTSP replay and multicast proxy support
  URL:=https://github.com/bigtan/iptv-rs
  DEPENDS:=+ca-bundle
endef

define Package/iptv/description
  iptv-rs is an IPTV proxy with playlist/XMLTV aggregation, UDP multicast
  proxying, Telecom FCC bootstrap support, RTSP replay, and management
  endpoints.
endef

define Build/Compile
endef

ifeq ($(filter aarch64 x86_64,$(ARCH)),)
define Build/Prepare
	$(error Prebuilt iptv-rs release binaries are only available for aarch64 and x86_64 musl)
endef
endif

define Package/iptv/conffiles
/etc/config/iptv
endef

define Package/iptv/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptv-rs $(1)/usr/bin/iptv-rs
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/iptv.config $(1)/etc/config/iptv
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/iptv.init $(1)/etc/init.d/iptv
endef

$(eval $(call BuildPackage,iptv))
