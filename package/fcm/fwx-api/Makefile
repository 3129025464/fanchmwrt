# FWX REST API Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-api
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-api
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX RESTful API
  DEPENDS:=+uhttpd +uhttpd-mod-ubus +rpcd +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-api/install
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) ./files/fwx-api.json $(1)/usr/share/rpcd/acl.d/fwx-api.json
	$(INSTALL_DIR) $(1)/www/api
	$(INSTALL_DATA) ./files/api-docs.html $(1)/www/api/index.html
endef

$(eval $(call BuildPackage,fwx-api))
