#!/bin/sh
. /lib/functions.sh
. /lib/functions/network.sh

CONFIG="fwx_qos"

get_wan_device() {
    local dev
    network_get_device dev wan
    [ -z "$dev" ] && dev=$(ip route | grep default | awk '{print $5}' | head -1)
    echo "$dev"
}

start_qos() {
    local enable download upload qdisc
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    config_get download global download_bandwidth 100000
    config_get upload global upload_bandwidth 50000
    config_get qdisc global qdisc "cake"
    
    local wan_dev=$(get_wan_device)
    [ -z "$wan_dev" ] && return 1
    
    tc qdisc del dev "$wan_dev" root 2>/dev/null
    tc qdisc del dev "$wan_dev" ingress 2>/dev/null
    
    if [ "$qdisc" = "cake" ]; then
        tc qdisc add dev "$wan_dev" root cake bandwidth "${upload}kbit" diffserv4
        tc qdisc add dev "$wan_dev" handle ffff: ingress
        tc filter add dev "$wan_dev" parent ffff: protocol ip prio 1 u32 match u32 0 0 police rate "${download}kbit" burst 256k drop flowid :1
    else
        tc qdisc add dev "$wan_dev" root handle 1: htb default 20
        tc class add dev "$wan_dev" parent 1: classid 1:1 htb rate "${upload}kbit"
        tc class add dev "$wan_dev" parent 1:1 classid 1:10 htb rate $((upload*30/100))kbit ceil "${upload}kbit" prio 1
        tc class add dev "$wan_dev" parent 1:1 classid 1:20 htb rate $((upload*50/100))kbit ceil "${upload}kbit" prio 2
        tc class add dev "$wan_dev" parent 1:1 classid 1:30 htb rate $((upload*20/100))kbit ceil "${upload}kbit" prio 3
    fi
    
    logger -t fwx-qos "QoS started on $wan_dev"
}

stop_qos() {
    local wan_dev=$(get_wan_device)
    [ -n "$wan_dev" ] && {
        tc qdisc del dev "$wan_dev" root 2>/dev/null
        tc qdisc del dev "$wan_dev" ingress 2>/dev/null
    }
    logger -t fwx-qos "QoS stopped"
}

case "$1" in
    start) start_qos ;;
    stop) stop_qos ;;
    restart) stop_qos; sleep 1; start_qos ;;
    status) tc -s qdisc show dev $(get_wan_device) 2>/dev/null ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
