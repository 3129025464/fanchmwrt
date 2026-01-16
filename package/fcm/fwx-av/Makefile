include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-av
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-av
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Antivirus Integration
  DEPENDS:=+fwxd +clamav
endef

define Package/fwx-av/description
  ClamAV integration for FanchMWRT.
  Provides file scanning and real-time protection.
endef

define Package/fwx-av/conffiles
/etc/config/fwx_av
endef

define Build/Compile
endef

define Package/fwx-av/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/fwx/av
	
	$(INSTALL_CONF) ./files/fwx_av.config $(1)/etc/config/fwx_av
	$(INSTALL_BIN) ./files/fwx-av.sh $(1)/usr/bin/fwx-av
	$(INSTALL_BIN) ./files/fwx-av-scan.sh $(1)/usr/bin/fwx-av-scan
	$(INSTALL_BIN) ./files/fwx-av.init $(1)/etc/init.d/fwx-av
endef

$(eval $(call BuildPackage,fwx-av))
