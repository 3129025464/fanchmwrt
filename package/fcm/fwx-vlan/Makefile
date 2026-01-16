# FWX VLAN Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-vlan
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-vlan
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FWX VLAN Management
  DEPENDS:=+kmod-8021q +ip-full +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-vlan/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-vlan.sh $(1)/usr/bin/fwx-vlan
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-vlan.init $(1)/etc/init.d/fwx-vlan
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_vlan.config $(1)/etc/config/fwx_vlan
endef

$(eval $(call BuildPackage,fwx-vlan))
