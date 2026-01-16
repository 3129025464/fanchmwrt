# FWX QoS Package
include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-qos
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-qos
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX QoS Bandwidth Management
  DEPENDS:=+tc-full +kmod-sched-core +kmod-sched-cake +libfwx_common
  PKGARCH:=all
endef

define Package/fwx-qos/description
  QoS and bandwidth management for FanchMWRT enterprise firewall.
endef

define Build/Compile
endef

define Package/fwx-qos/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-qos.sh $(1)/usr/bin/fwx-qos
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-qos.init $(1)/etc/init.d/fwx-qos
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_qos.config $(1)/etc/config/fwx_qos
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_DATA) ./files/fwx-qos.hotplug $(1)/etc/hotplug.d/iface/99-fwx-qos
endef

define Package/fwx-qos/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/fwx-qos enable
exit 0
endef

$(eval $(call BuildPackage,fwx-qos))
