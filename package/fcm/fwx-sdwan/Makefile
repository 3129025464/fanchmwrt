# FWX SD-WAN Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-sdwan
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-sdwan
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=FWX SD-WAN
  DEPENDS:=+mwan3 +ip-full +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-sdwan/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-sdwan.sh $(1)/usr/bin/fwx-sdwan
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-sdwan.init $(1)/etc/init.d/fwx-sdwan
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_sdwan.config $(1)/etc/config/fwx_sdwan
endef

$(eval $(call BuildPackage,fwx-sdwan))
