# FWX WireGuard VPN Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-vpn
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-vpn
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=FWX WireGuard VPN
  DEPENDS:=+wireguard-tools +kmod-wireguard +qrencode +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-vpn/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-vpn.sh $(1)/usr/bin/fwx-vpn
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-vpn.init $(1)/etc/init.d/fwx-vpn
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_vpn.config $(1)/etc/config/fwx_vpn
	$(INSTALL_DIR) $(1)/etc/fwx/vpn/clients
endef

$(eval $(call BuildPackage,fwx-vpn))
