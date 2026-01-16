#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_sdwan"
MWAN3_CONFIG="mwan3"

generate_mwan3() {
    > "/etc/config/$MWAN3_CONFIG"
    uci set $MWAN3_CONFIG.globals=globals
    uci set $MWAN3_CONFIG.globals.mmx_mask='0x3F00'
    
    config_load "$CONFIG"
    config_foreach gen_interface interface
    config_foreach gen_member interface
    config_foreach gen_policy policy
    
    uci commit $MWAN3_CONFIG
}

gen_interface() {
    local cfg="$1"
    local enable track_ip
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    config_get track_ip "$cfg" track_ip "8.8.8.8"
    
    uci set $MWAN3_CONFIG.$cfg=interface
    uci set $MWAN3_CONFIG.$cfg.enabled='1'
    uci add_list $MWAN3_CONFIG.$cfg.track_ip="$track_ip"
    uci set $MWAN3_CONFIG.$cfg.reliability='1'
    uci set $MWAN3_CONFIG.$cfg.count='3'
    uci set $MWAN3_CONFIG.$cfg.timeout='2'
    uci set $MWAN3_CONFIG.$cfg.interval='5'
    uci set $MWAN3_CONFIG.$cfg.down='3'
    uci set $MWAN3_CONFIG.$cfg.up='3'
}

gen_member() {
    local cfg="$1"
    local enable weight
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    config_get weight "$cfg" weight "1"
    
    uci set $MWAN3_CONFIG.${cfg}_m=member
    uci set $MWAN3_CONFIG.${cfg}_m.interface="$cfg"
    uci set $MWAN3_CONFIG.${cfg}_m.weight="$weight"
}

gen_policy() {
    local cfg="$1"
    local enable interfaces
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    config_get interfaces "$cfg" interface
    
    uci set $MWAN3_CONFIG.$cfg=policy
    for iface in $interfaces; do
        uci add_list $MWAN3_CONFIG.$cfg.use_member="${iface}_m"
    done
}

start_sdwan() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    generate_mwan3
    /etc/init.d/mwan3 restart
    logger -t fwx-sdwan "SD-WAN started"
}

stop_sdwan() {
    /etc/init.d/mwan3 stop
    logger -t fwx-sdwan "SD-WAN stopped"
}

case "$1" in
    start) start_sdwan ;;
    stop) stop_sdwan ;;
    restart) stop_sdwan; start_sdwan ;;
    status) /usr/sbin/mwan3 status 2>/dev/null ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
