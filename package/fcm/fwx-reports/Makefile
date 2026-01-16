# FWX Reports Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-reports
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-reports
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Reports
  DEPENDS:=+libfwx_common
  PKGARCH:=all
endef

define Build/Compile
endef

define Package/fwx-reports/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-reports.sh $(1)/usr/bin/fwx-reports
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-reports.init $(1)/etc/init.d/fwx-reports
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_reports.config $(1)/etc/config/fwx_reports
	$(INSTALL_DIR) $(1)/www/fwx/reports
endef

$(eval $(call BuildPackage,fwx-reports))
