# FWX DDoS Protection Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-ddos
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-ddos
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX DDoS Protection
  DEPENDS:=+nftables +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-ddos/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-ddos.sh $(1)/usr/bin/fwx-ddos
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-ddos.init $(1)/etc/init.d/fwx-ddos
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_ddos.config $(1)/etc/config/fwx_ddos
endef

$(eval $(call BuildPackage,fwx-ddos))
