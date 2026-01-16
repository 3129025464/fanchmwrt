include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-threat
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-threat
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Threat Intelligence Module
  DEPENDS:=+fwxd +curl +ca-bundle +nftables-json
endef

define Package/fwx-threat/description
  Threat intelligence module for FanchMWRT.
  Provides IP/Domain blacklist filtering with auto-update.
endef

define Package/fwx-threat/conffiles
/etc/config/threat_intel
endef

define Build/Compile
endef

define Package/fwx-threat/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/fwx/threat
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	
	$(INSTALL_CONF) ./files/threat_intel.config $(1)/etc/config/threat_intel
	$(INSTALL_BIN) ./files/threat_update.sh $(1)/usr/bin/fwx-threat-update
	$(INSTALL_BIN) ./files/threat_apply.sh $(1)/usr/bin/fwx-threat-apply
	$(INSTALL_BIN) ./files/threat.init $(1)/etc/init.d/fwx-threat
	$(INSTALL_BIN) ./files/uci-defaults/99_fwx_threat $(1)/etc/uci-defaults/
endef

$(eval $(call BuildPackage,fwx-threat))
