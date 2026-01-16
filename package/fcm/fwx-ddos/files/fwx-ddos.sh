#!/bin/sh
# FWX DDoS Protection Module

. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_ddos"
NFT_TABLE="fwx_ddos"
NFT_FILE="/tmp/fwx-ddos.nft"
LOG_TAG="fwx-ddos"

log() {
    if type fwx_log >/dev/null 2>&1; then
        fwx_log "$LOG_TAG" "info" "$1"
    else
        logger -t "$LOG_TAG" "$1"
    fi
}

generate_ruleset() {
    local syn_rate udp_rate icmp_rate conn_limit
    
    config_load "$CONFIG"
    config_get syn_rate global syn_rate "50/second"
    config_get udp_rate global udp_rate "100/second"
    config_get icmp_rate global icmp_rate "10/second"
    config_get conn_limit global conn_limit "100"
    
    cat > "$NFT_FILE" <<EOF
# FWX DDoS Protection Ruleset
table inet $NFT_TABLE {
    set banned {
        type ipv4_addr
        flags timeout
    }
    
    set conn_track {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }
    
    chain input {
        type filter hook input priority -150; policy accept;
        
        # Drop banned IPs
        ip saddr @banned counter drop
        
        # Drop invalid packets
        ct state invalid counter drop
        
        # SYN flood protection
        tcp flags syn limit rate $syn_rate burst 100 packets accept
        tcp flags syn counter log prefix "[FWX-DDOS:SYN] " drop
        
        # UDP flood protection
        ip protocol udp limit rate $udp_rate burst 200 packets accept
        ip protocol udp ct state new counter log prefix "[FWX-DDOS:UDP] " drop
        
        # ICMP flood protection
        ip protocol icmp limit rate $icmp_rate burst 20 packets accept
        ip protocol icmp counter log prefix "[FWX-DDOS:ICMP] " drop
        
        # Connection limit per IP
        ct state new add @conn_track { ip saddr } \\
            limit rate over $conn_limit/minute \\
            counter log prefix "[FWX-DDOS:CONN] " drop
    }
}
EOF
}

start_ddos() {
    local enable syncookie
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && { log "DDoS protection disabled"; return 0; }
    
    # Enable SYN cookies
    config_get_bool syncookie global syncookie 1
    [ "$syncookie" = "1" ] && echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    
    # Generate and apply ruleset
    generate_ruleset
    
    nft delete table inet $NFT_TABLE 2>/dev/null
    if nft -f "$NFT_FILE" 2>/dev/null; then
        log "DDoS protection started"
    else
        log "Failed to start DDoS protection"
        return 1
    fi
}

stop_ddos() {
    nft delete table inet $NFT_TABLE 2>/dev/null
    log "DDoS protection stopped"
}

ban_ip() {
    local ip="$1" duration="${2:-3600}" reason="${3:-manual}"
    
    # Validate IP
    echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || {
        echo "Invalid IP: $ip"
        return 1
    }
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        nft add element inet $NFT_TABLE banned "{ $ip timeout ${duration}s }" 2>/dev/null
        log "Banned $ip for ${duration}s (reason: $reason)"
        echo "Banned: $ip for ${duration}s"
        
        # Send alert
        if type fwx_alert >/dev/null 2>&1; then
            fwx_alert "fwx-ddos" "warning" "synflood" "$ip" "IP banned for ${duration}s: $reason"
        fi
    else
        echo "DDoS protection not running"
        return 1
    fi
}

unban_ip() {
    local ip="$1"
    [ -n "$ip" ] || { echo "Usage: $0 unban <ip>"; return 1; }
    
    nft delete element inet $NFT_TABLE banned "{ $ip }" 2>/dev/null
    log "Unbanned $ip"
    echo "Unbanned: $ip"
}

status_ddos() {
    echo "=== FWX DDoS Protection Status ==="
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        echo "Status: Running"
        echo ""
        echo "Banned IPs:"
        nft list set inet $NFT_TABLE banned 2>/dev/null | grep -E "elements|timeout"
        echo ""
        echo "Statistics:"
        nft list chain inet $NFT_TABLE input 2>/dev/null | grep -E "counter|packets"
    else
        echo "Status: Stopped"
    fi
    
    echo ""
    echo "SYN Cookies: $(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo 'N/A')"
}

case "$1" in
    start) start_ddos ;;
    stop) stop_ddos ;;
    restart) stop_ddos; sleep 1; start_ddos ;;
    ban) ban_ip "$2" "$3" ;;
    unban) unban_ip "$2" ;;
    status) status_ddos ;;
    *) echo "Usage: $0 {start|stop|restart|ban <ip> [duration]|unban <ip>|status}" ;;
esac
