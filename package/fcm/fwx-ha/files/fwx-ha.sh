#!/bin/sh
. /lib/functions.sh
. /lib/functions/network.sh

CONFIG="fwx_ha"
KEEPALIVED_CONF="/etc/keepalived/keepalived.conf"
STATUS_FILE="/tmp/fwx/ha/status"

generate_keepalived() {
    local interface vrid priority auth_pass virtual_ips preempt
    config_load "$CONFIG"
    
    config_get interface vrrp interface "lan"
    config_get vrid vrrp virtual_router_id "51"
    config_get priority global priority "100"
    config_get auth_pass vrrp auth_pass "fwxha123"
    config_get virtual_ips vrrp virtual_ip
    config_get_bool preempt global preempt 1
    
    local ifname
    network_get_device ifname "$interface"
    [ -z "$ifname" ] && ifname="$interface"
    
    mkdir -p /etc/keepalived /etc/fwx/ha/scripts
    
    cat > /etc/fwx/ha/scripts/notify.sh << 'EOF'
#!/bin/sh
STATE=$3
echo "$STATE" > /tmp/fwx/ha/status
logger -t fwx-ha "State: $STATE"
EOF
    chmod +x /etc/fwx/ha/scripts/notify.sh
    
    cat > "$KEEPALIVED_CONF" << EOF
global_defs {
    router_id FWX_HA
}

vrrp_instance FWX_HA {
    state BACKUP
    interface $ifname
    virtual_router_id $vrid
    priority $priority
EOF

    [ "$preempt" != "1" ] && echo "    nopreempt" >> "$KEEPALIVED_CONF"
    
    cat >> "$KEEPALIVED_CONF" << EOF
    authentication {
        auth_type PASS
        auth_pass $auth_pass
    }
    virtual_ipaddress {
EOF

    for vip in $virtual_ips; do
        echo "        $vip" >> "$KEEPALIVED_CONF"
    done
    
    cat >> "$KEEPALIVED_CONF" << EOF
    }
    notify /etc/fwx/ha/scripts/notify.sh
}
EOF
}

start_ha() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    mkdir -p /tmp/fwx/ha
    generate_keepalived
    /etc/init.d/keepalived start
    /etc/init.d/conntrackd start 2>/dev/null
    echo "BACKUP" > "$STATUS_FILE"
    logger -t fwx-ha "HA started"
}

stop_ha() {
    /etc/init.d/keepalived stop 2>/dev/null
    /etc/init.d/conntrackd stop 2>/dev/null
    rm -f "$STATUS_FILE"
    logger -t fwx-ha "HA stopped"
}

show_status() {
    echo "=== HA Status ==="
    [ -f "$STATUS_FILE" ] && echo "State: $(cat $STATUS_FILE)" || echo "State: Unknown"
    echo ""
    echo "keepalived: $(pidof keepalived >/dev/null && echo Running || echo Stopped)"
    echo "conntrackd: $(pidof conntrackd >/dev/null && echo Running || echo Stopped)"
}

case "$1" in
    start) start_ha ;;
    stop) stop_ha ;;
    restart) stop_ha; sleep 2; start_ha ;;
    status) show_status ;;
    failover) /etc/init.d/keepalived stop; sleep 2; /etc/init.d/keepalived start ;;
    *) echo "Usage: $0 {start|stop|restart|status|failover}" ;;
esac
