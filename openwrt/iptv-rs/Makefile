include $(TOPDIR)/rules.mk

PKG_NAME:=iptv-rs
PKG_VERSION:=0.3.2
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://github.com/bigtan/iptv-rs/releases/download/v$(PKG_VERSION)

ifeq ($(ARCH),aarch64)
  PKG_SOURCE:=$(PKG_NAME)-aarch64-unknown-linux-musl.zip
  PKG_HASH:=157ef9aa0d0f18f8977759194c80da1e272350dde14f6ec0dda1116a0687f2bf
else ifeq ($(ARCH),x86_64)
  PKG_SOURCE:=$(PKG_NAME)-x86_64-unknown-linux-musl.zip
  PKG_HASH:=6eae63281a9e818c98ec38d3ac8d6a2c17887e2c93449c91d4a893c7b5d81e17
else
  PKG_SOURCE:=unsupported-$(ARCH).zip
  PKG_HASH:=skip
endif

UNPACK_CMD=unzip -q -d $(PKG_BUILD_DIR) $(DL_DIR)/$(PKG_SOURCE)

PKG_LICENSE:=AGPL-3.0-only
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=iptv-rs maintainers

include $(INCLUDE_DIR)/package.mk

define Package/iptv-rs
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Rust IPTV proxy with RTSP replay and multicast proxy support
  URL:=https://github.com/bigtan/iptv-rs
  DEPENDS:=+ca-bundle
endef

define Package/iptv-rs/description
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

define Package/iptv-rs/conffiles
/etc/config/iptv-rs
endef

define Package/iptv-rs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/iptv-rs $(1)/usr/bin/iptv-rs
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/iptv-rs.config $(1)/etc/config/iptv-rs
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/iptv-rs.init $(1)/etc/init.d/iptv-rs
endef

$(eval $(call BuildPackage,iptv-rs))
