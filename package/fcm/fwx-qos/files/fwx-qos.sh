#!/bin/sh
# FWX QoS Bandwidth Management

. /lib/functions.sh
. /lib/functions/network.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_qos"
LOG_TAG="fwx-qos"

log() {
    if type fwx_log >/dev/null 2>&1; then
        fwx_log "$LOG_TAG" "info" "$1"
    else
        logger -t "$LOG_TAG" "$1"
    fi
}

get_wan_device() {
    local dev
    network_get_device dev wan 2>/dev/null
    [ -z "$dev" ] && dev=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    echo "$dev"
}

cleanup_qos() {
    local dev="$1"
    [ -n "$dev" ] || return
    tc qdisc del dev "$dev" root 2>/dev/null
    tc qdisc del dev "$dev" ingress 2>/dev/null
}

setup_cake() {
    local dev="$1" upload="$2" download="$3"
    
    tc qdisc add dev "$dev" root cake bandwidth "${upload}kbit" diffserv4
    tc qdisc add dev "$dev" handle ffff: ingress
    tc filter add dev "$dev" parent ffff: protocol ip prio 1 u32 match u32 0 0 \
        police rate "${download}kbit" burst 256k drop flowid :1
    
    log "CAKE QoS: up=${upload}k down=${download}k on $dev"
}

setup_htb() {
    local dev="$1" upload="$2" download="$3"
    
    tc qdisc add dev "$dev" root handle 1: htb default 30
    tc class add dev "$dev" parent 1: classid 1:1 htb rate "${upload}kbit"
    tc class add dev "$dev" parent 1:1 classid 1:10 htb rate $((upload*20/100))kbit ceil "${upload}kbit" prio 1
    tc class add dev "$dev" parent 1:1 classid 1:20 htb rate $((upload*50/100))kbit ceil "${upload}kbit" prio 2
    tc class add dev "$dev" parent 1:1 classid 1:30 htb rate $((upload*30/100))kbit ceil "${upload}kbit" prio 3
    
    tc qdisc add dev "$dev" handle ffff: ingress
    tc filter add dev "$dev" parent ffff: protocol ip prio 1 u32 match u32 0 0 \
        police rate "${download}kbit" burst 256k drop flowid :1
    
    log "HTB QoS: up=${upload}k down=${download}k on $dev"
}

start_qos() {
    local enable download upload qdisc
    
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && { log "QoS disabled"; return 0; }
    
    config_get download global download_bandwidth 100000
    config_get upload global upload_bandwidth 50000
    config_get qdisc global qdisc "cake"
    
    local wan_dev=$(get_wan_device)
    [ -z "$wan_dev" ] && { log "No WAN device"; return 1; }
    
    cleanup_qos "$wan_dev"
    
    case "$qdisc" in
        cake) setup_cake "$wan_dev" "$upload" "$download" ;;
        htb) setup_htb "$wan_dev" "$upload" "$download" ;;
        *) log "Unknown qdisc: $qdisc"; return 1 ;;
    esac
    
    log "QoS started on $wan_dev"
}

stop_qos() {
    local wan_dev=$(get_wan_device)
    [ -n "$wan_dev" ] && cleanup_qos "$wan_dev"
    log "QoS stopped"
}

status_qos() {
    local wan_dev=$(get_wan_device)
    echo "=== FWX QoS Status ==="
    echo "WAN: ${wan_dev:-Not found}"
    [ -n "$wan_dev" ] && tc -s qdisc show dev "$wan_dev" 2>/dev/null
}

case "$1" in
    start) start_qos ;;
    stop) stop_qos ;;
    restart) stop_qos; sleep 1; start_qos ;;
    status) status_qos ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
