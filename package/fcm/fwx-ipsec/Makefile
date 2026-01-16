# FWX IPSec VPN Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-ipsec
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-ipsec
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=FWX IPSec VPN
  DEPENDS:=+strongswan +strongswan-charon +strongswan-swanctl +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-ipsec/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-ipsec.sh $(1)/usr/bin/fwx-ipsec
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-ipsec.init $(1)/etc/init.d/fwx-ipsec
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_ipsec.config $(1)/etc/config/fwx_ipsec
	$(INSTALL_DIR) $(1)/etc/fwx/ipsec
endef

$(eval $(call BuildPackage,fwx-ipsec))
