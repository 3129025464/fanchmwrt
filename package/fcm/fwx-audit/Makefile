# FWX Log Audit Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-audit
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-audit
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Log Audit
  DEPENDS:=+logd +libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-audit/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-audit.sh $(1)/usr/bin/fwx-audit
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-audit.init $(1)/etc/init.d/fwx-audit
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_audit.config $(1)/etc/config/fwx_audit
	$(INSTALL_DIR) $(1)/var/log/fwx
endef

$(eval $(call BuildPackage,fwx-audit))
