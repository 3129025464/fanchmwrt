include $(TOPDIR)/rules.mk

PKG_NAME:=fwx-ids
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/fwx-ids
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX Intrusion Detection System
  DEPENDS:=+fwxd +nftables-json
endef

define Package/fwx-ids/description
  Lightweight IDS module for FanchMWRT.
  Detects port scans, SYN floods, brute force attacks.
endef

define Package/fwx-ids-suricata
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Firewall
  TITLE:=FWX IDS with Suricata backend
  DEPENDS:=+fwx-ids +suricata
endef

define Package/fwx-ids-suricata/description
  Full IDS/IPS using Suricata engine.
  Requires 512MB+ RAM.
endef

define Package/fwx-ids/conffiles
/etc/config/fwx_ids
/etc/config/fwx_notify
/etc/config/fwx_traffic
endef

define Build/Compile
endef

define Package/fwx-ids/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/fwx/ids
	$(INSTALL_DIR) $(1)/tmp/log
	
	$(INSTALL_CONF) ./files/fwx_ids.config $(1)/etc/config/fwx_ids
	$(INSTALL_CONF) ./files/fwx_notify.config $(1)/etc/config/fwx_notify
	$(INSTALL_CONF) ./files/fwx_traffic.config $(1)/etc/config/fwx_traffic
	$(INSTALL_BIN) ./files/fwx-ids.sh $(1)/usr/bin/fwx-ids
	$(INSTALL_BIN) ./files/fwx-notify.sh $(1)/usr/bin/fwx-notify
	$(INSTALL_BIN) ./files/fwx-ids.init $(1)/etc/init.d/fwx-ids
endef

define Package/fwx-ids-suricata/conffiles
/etc/config/fwx_suricata
endef

define Package/fwx-ids-suricata/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/fwx/ids/suricata
	$(INSTALL_DIR) $(1)/etc/fwx/ids/suricata/rules
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/tmp/log/suricata
	
	$(INSTALL_CONF) ./files/fwx_suricata.config $(1)/etc/config/fwx_suricata
	$(INSTALL_BIN) ./files/fwx-suricata-manager.sh $(1)/usr/bin/fwx-suricata
	$(INSTALL_CONF) ./files/suricata.yaml $(1)/etc/fwx/ids/suricata/
endef

$(eval $(call BuildPackage,fwx-ids))
$(eval $(call BuildPackage,fwx-ids-suricata))
