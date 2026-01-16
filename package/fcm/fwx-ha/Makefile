# FWX High Availability Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-ha
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-ha
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=FWX High Availability
  DEPENDS:=+keepalived +conntrackd +ip-full +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-ha/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-ha.sh $(1)/usr/bin/fwx-ha
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-ha.init $(1)/etc/init.d/fwx-ha
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_ha.config $(1)/etc/config/fwx_ha
	$(INSTALL_DIR) $(1)/etc/fwx/ha/scripts
endef

$(eval $(call BuildPackage,fwx-ha))
