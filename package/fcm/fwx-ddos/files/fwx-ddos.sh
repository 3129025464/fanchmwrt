#!/bin/sh
. /lib/functions.sh

CONFIG="fwx_ddos"

start_ddos() {
    local enable syn_rate udp_rate icmp_rate conn_limit syncookie
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    config_get syn_rate global syn_rate "50/second"
    config_get udp_rate global udp_rate "100/second"
    config_get icmp_rate global icmp_rate "10/second"
    config_get conn_limit global conn_limit "100"
    config_get_bool syncookie global syncookie 1
    
    [ "$syncookie" = "1" ] && echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    
    nft -f - << EOF
table inet fwx_ddos {
    set banned { type ipv4_addr; flags timeout; }
    
    chain input {
        type filter hook input priority -150; policy accept;
        ip saddr @banned drop
        ct state invalid drop
        tcp flags syn limit rate $syn_rate accept
        tcp flags syn drop
        ip protocol udp limit rate $udp_rate accept
        ip protocol icmp limit rate $icmp_rate accept
        ct count over $conn_limit drop
    }
}
EOF
    logger -t fwx-ddos "DDoS protection started"
}

stop_ddos() {
    nft delete table inet fwx_ddos 2>/dev/null
    logger -t fwx-ddos "DDoS protection stopped"
}

ban_ip() {
    local ip="$1" duration="${2:-3600}"
    nft add element inet fwx_ddos banned "{ $ip timeout ${duration}s }" 2>/dev/null
    logger -t fwx-ddos "Banned $ip for ${duration}s"
}

unban_ip() {
    local ip="$1"
    nft delete element inet fwx_ddos banned "{ $ip }" 2>/dev/null
    logger -t fwx-ddos "Unbanned $ip"
}

case "$1" in
    start) start_ddos ;;
    stop) stop_ddos ;;
    restart) stop_ddos; start_ddos ;;
    ban) ban_ip "$2" "$3" ;;
    unban) unban_ip "$2" ;;
    status) nft list table inet fwx_ddos 2>/dev/null ;;
    *) echo "Usage: $0 {start|stop|restart|ban|unban|status}" ;;
esac
