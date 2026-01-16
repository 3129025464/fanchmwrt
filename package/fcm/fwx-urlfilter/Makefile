# FWX URL Filter Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-urlfilter
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-urlfilter
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX URL Filter
  DEPENDS:=+dnsmasq-full +curl +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-urlfilter/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-urlfilter.sh $(1)/usr/bin/fwx-urlfilter
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-urlfilter.init $(1)/etc/init.d/fwx-urlfilter
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_urlfilter.config $(1)/etc/config/fwx_urlfilter
	$(INSTALL_DIR) $(1)/etc/fwx/urlfilter/lists
endef

$(eval $(call BuildPackage,fwx-urlfilter))
