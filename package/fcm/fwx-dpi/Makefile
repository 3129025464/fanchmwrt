# SPDX-License-Identifier: GPL-2.0-or-later

include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-dpi
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_MAINTAINER:=FanchMWRT <www.fanchmwrt.com>
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/fwx-dpi
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Deep Packet Inspection
  DEPENDS:=+ndpi-netfilter +iptables-mod-ndpi +kmod-ipt-ndpi +libfwx_common
  PKGARCH:=all
endef

define Package/fwx-dpi/description
  Deep Packet Inspection module for FanchMWRT using nDPI.
  Identifies 300+ applications and protocols.
endef

define Package/fwx-dpi/conffiles
/etc/config/fwx_dpi
endef

define Build/Compile
endef

define Package/fwx-dpi/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/fwx-dpi.sh $(1)/usr/bin/fwx-dpi

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/fwx_dpi.config $(1)/etc/config/fwx_dpi

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/fwx-dpi.init $(1)/etc/init.d/fwx-dpi

	$(INSTALL_DIR) $(1)/etc/fwx/dpi
	$(INSTALL_DATA) ./files/app_categories.conf $(1)/etc/fwx/dpi/
endef

$(eval $(call BuildPackage,fwx-dpi))
