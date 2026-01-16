#!/bin/sh
. /lib/functions.sh

CONFIG="fwx_vlan"

create_vlan() {
    local cfg="$1"
    local enable name vid parent ipaddr netmask dhcp isolate
    
    config_get_bool enable "$cfg" enable 1
    [ "$enable" != "1" ] && return
    
    config_get name "$cfg" name
    config_get vid "$cfg" vid
    config_get parent "$cfg" parent "eth0"
    config_get ipaddr "$cfg" ipaddr
    config_get netmask "$cfg" netmask "255.255.255.0"
    config_get_bool dhcp "$cfg" dhcp 0
    config_get_bool isolate "$cfg" isolate 0
    
    [ -z "$name" ] || [ -z "$vid" ] && return
    
    local iface="${parent}.${vid}"
    
    ip link add link "$parent" name "$iface" type vlan id "$vid" 2>/dev/null
    ip link set "$iface" up
    [ -n "$ipaddr" ] && ip addr add "$ipaddr/${netmask}" dev "$iface" 2>/dev/null
    
    # UCI network config
    uci -q delete network."vlan_$name"
    uci set network."vlan_$name"=interface
    uci set network."vlan_$name".proto='static'
    uci set network."vlan_$name".device="$iface"
    uci set network."vlan_$name".ipaddr="$ipaddr"
    uci set network."vlan_$name".netmask="$netmask"
    
    # Firewall zone
    uci -q delete firewall."vlan_${name}_zone"
    uci set firewall."vlan_${name}_zone"=zone
    uci set firewall."vlan_${name}_zone".name="vlan_$name"
    uci set firewall."vlan_${name}_zone".network="vlan_$name"
    uci set firewall."vlan_${name}_zone".input='ACCEPT'
    uci set firewall."vlan_${name}_zone".output='ACCEPT'
    uci set firewall."vlan_${name}_zone".forward='REJECT'
    
    logger -t fwx-vlan "Created VLAN $name ($iface)"
}

delete_vlan() {
    local cfg="$1"
    local name vid parent
    config_get name "$cfg" name
    config_get vid "$cfg" vid
    config_get parent "$cfg" parent "eth0"
    
    local iface="${parent}.${vid}"
    ip link del "$iface" 2>/dev/null
    uci -q delete network."vlan_$name"
    uci -q delete firewall."vlan_${name}_zone"
}

start_vlans() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 1
    [ "$enable" != "1" ] && return 0
    
    modprobe 8021q 2>/dev/null
    config_foreach create_vlan vlan
    uci commit network
    uci commit firewall
    /etc/init.d/network reload 2>/dev/null
}

stop_vlans() {
    config_load "$CONFIG"
    config_foreach delete_vlan vlan
    uci commit network
    uci commit firewall
}

case "$1" in
    start) start_vlans ;;
    stop) stop_vlans ;;
    restart) stop_vlans; start_vlans ;;
    list) ip -d link show type vlan ;;
    *) echo "Usage: $0 {start|stop|restart|list}" ;;
esac
