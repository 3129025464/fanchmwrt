# FWX RBAC Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-rbac
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-rbac
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Role-Based Access Control
  DEPENDS:=+rpcd +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-rbac/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-rbac.sh $(1)/usr/bin/fwx-rbac
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_rbac.config $(1)/etc/config/fwx_rbac
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/fwx-rbac.json $(1)/usr/share/rpcd/acl.d/fwx-rbac.json
endef

$(eval $(call BuildPackage,fwx-rbac))
