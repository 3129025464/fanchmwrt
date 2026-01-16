#!/bin/sh
# FWX Lightweight IDS/IPS
# Implements intrusion detection and prevention using nftables

. /lib/functions.sh
. /lib/fwx/nft_atomic.sh 2>/dev/null || true
. /lib/fwx/common.sh 2>/dev/null || true

NFT_TABLE="fwx_ids"
NFT_FILE="/tmp/fwx-ids.nft"
LOG_TAG="fwx-ids"

log() {
    local level="$1" msg="$2"
    if type fwx_log >/dev/null 2>&1; then
        fwx_log "$LOG_TAG" "$level" "$msg"
    else
        logger -t "$LOG_TAG" -p "daemon.$level" "$msg"
    fi
}

alert() {
    local type="$1" src="$2" detail="$3"
    log "warn" "ALERT: $type from $src - $detail"
    if type fwx_alert >/dev/null 2>&1; then
        fwx_alert "$type" "$src" "$detail"
    else
        ubus call fwx alert "{\"type\":\"$type\",\"src\":\"$src\",\"detail\":\"$detail\"}" 2>/dev/null
    fi
}

acquire_lock() {
    if type fwx_lock >/dev/null 2>&1; then
        fwx_lock "$NFT_TABLE" 30
    elif type nft_lock >/dev/null 2>&1; then
        nft_lock "$NFT_TABLE" 30
    else
        local timeout=30 i=0
        while [ $i -lt $timeout ]; do
            if mkdir "/tmp/fwx-ids.lock" 2>/dev/null; then
                echo $$ > "/tmp/fwx-ids.lock/pid"
                return 0
            fi
            sleep 1
            i=$((i + 1))
        done
        return 1
    fi
}

release_lock() {
    if type fwx_unlock >/dev/null 2>&1; then
        fwx_unlock "$NFT_TABLE"
    elif type nft_unlock >/dev/null 2>&1; then
        nft_unlock "$NFT_TABLE"
    else
        rm -rf "/tmp/fwx-ids.lock"
    fi
}

# 导出现有 set 数据
export_existing_sets() {
    local sets_file="$1"
    : > "$sets_file"
    
    nft list table inet $NFT_TABLE >/dev/null 2>&1 || return 0
    
    # 导出 blocked_ips
    nft list set inet $NFT_TABLE blocked_ips 2>/dev/null | \
        sed -n 's/.*elements = { \(.*\) }/\1/p' | tr ',' '\n' | \
        sed 's/^ *//' | grep -v '^$' | while read elem; do
            echo "add element inet $NFT_TABLE blocked_ips { $elem }"
        done >> "$sets_file"
    
    # 导出 ssh_blocked
    nft list set inet $NFT_TABLE ssh_blocked 2>/dev/null | \
        sed -n 's/.*elements = { \(.*\) }/\1/p' | tr ',' '\n' | \
        sed 's/^ *//' | grep -v '^$' | while read elem; do
            echo "add element inet $NFT_TABLE ssh_blocked { $elem }"
        done >> "$sets_file"
}

generate_ruleset() {
    local enable
    config_load fwx_ids
    config_get enable global enable "0"
    [ "$enable" = "1" ] || return 1
    
    cat > "$NFT_FILE" <<'EOF'
# FWX IDS Atomic Ruleset
table inet fwx_ids {
    set blocked_ips {
        type ipv4_addr
        flags timeout
    }
    
    set portscan_track {
        type ipv4_addr . inet_service
        flags dynamic, timeout
        timeout 60s
    }
    
    set ssh_track {
        type ipv4_addr
        flags dynamic, timeout
        timeout 60s
    }
    
    set ssh_blocked {
        type ipv4_addr
        flags timeout
    }
    
    chain input {
        type filter hook input priority -100; policy accept;
        
        # Drop already blocked IPs
        ip saddr @blocked_ips drop
        ip saddr @ssh_blocked tcp dport 22 drop
EOF

    # Port scan protection
    local ps_enable threshold interval block_time
    config_get ps_enable portscan enable "0"
    if [ "$ps_enable" = "1" ]; then
        config_get threshold portscan threshold "20"
        config_get interval portscan interval "60"
        config_get block_time portscan block_time "3600"
        log "info" "Port scan protection: threshold=$threshold/${interval}s"
        cat >> "$NFT_FILE" <<EOF
        
        # Port scan protection
        ct state new add @portscan_track { ip saddr . tcp dport timeout ${interval}s } \\
            limit rate over ${threshold}/minute \\
            add @blocked_ips { ip saddr timeout ${block_time}s } \\
            log prefix "[FWX-IDS:PORTSCAN] " drop
EOF
    fi

    # SYN flood protection
    local syn_enable rate burst action
    config_get syn_enable synflood enable "0"
    if [ "$syn_enable" = "1" ]; then
        config_get rate synflood rate "25"
        config_get burst synflood burst "50"
        config_get action synflood action "drop"
        log "info" "SYN flood protection: rate=${rate}/s burst=$burst"
        cat >> "$NFT_FILE" <<EOF
        
        # SYN flood protection
        tcp flags syn ct state new limit rate over ${rate}/second burst $burst packets \\
            log prefix "[FWX-IDS:SYNFLOOD] " $action
EOF
    fi

    # SSH brute force protection
    local bf_enable ssh_enable ssh_max_retry ssh_block_time
    config_get bf_enable bruteforce enable "0"
    if [ "$bf_enable" = "1" ]; then
        config_get ssh_enable bruteforce ssh_enable "1"
        config_get ssh_max_retry bruteforce ssh_max_retry "5"
        config_get ssh_block_time bruteforce ssh_block_time "3600"
        
        if [ "$ssh_enable" = "1" ]; then
            log "info" "SSH brute force protection: max=$ssh_max_retry"
            cat >> "$NFT_FILE" <<EOF
        
        # SSH brute force protection
        tcp dport 22 ct state new add @ssh_track { ip saddr timeout 60s } \\
            limit rate over ${ssh_max_retry}/minute \\
            add @ssh_blocked { ip saddr timeout ${ssh_block_time}s } \\
            log prefix "[FWX-IDS:SSH-BRUTE] " drop
EOF
        fi
    fi

    # ICMP flood protection
    local icmp_enable icmp_rate icmp_burst
    config_get icmp_enable icmpflood enable "0"
    if [ "$icmp_enable" = "1" ]; then
        config_get icmp_rate icmpflood rate "10"
        config_get icmp_burst icmpflood burst "20"
        log "info" "ICMP flood protection: rate=${icmp_rate}/s"
        cat >> "$NFT_FILE" <<EOF
        
        # ICMP flood protection
        ip protocol icmp limit rate over ${icmp_rate}/second burst $icmp_burst packets \\
            log prefix "[FWX-IDS:ICMPFLOOD] " drop
EOF
    fi

    # Close chain and table
    cat >> "$NFT_FILE" <<'EOF'
    }
}
EOF
    return 0
}

apply_atomic() {
    local sets_backup="/tmp/fwx-ids-sets.nft"
    export_existing_sets "$sets_backup"
    
    # Delete old table and load new
    nft delete table inet $NFT_TABLE 2>/dev/null
    
    if nft -f "$NFT_FILE" 2>/dev/null; then
        [ -s "$sets_backup" ] && nft -f "$sets_backup" 2>/dev/null
        log "info" "Ruleset applied atomically"
        return 0
    else
        log "error" "Failed to apply ruleset"
        return 1
    fi
}

start_ids() {
    config_load fwx_ids
    local enable
    config_get enable global enable "0"
    
    [ "$enable" = "1" ] || {
        log "info" "FWX IDS disabled"
        return 0
    }
    
    log "info" "Starting FWX IDS"
    acquire_lock || { log "error" "Failed to acquire lock"; return 1; }
    
    if generate_ruleset && apply_atomic; then
        log "info" "FWX IDS started"
    else
        log "error" "Failed to start IDS"
        release_lock
        return 1
    fi
    
    release_lock
}

stop_ids() {
    log "info" "Stopping FWX IDS"
    acquire_lock || return 1
    nft delete table inet $NFT_TABLE 2>/dev/null
    release_lock
}

status_ids() {
    echo "=== FWX IDS Status ==="
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        echo "Status: Running"
        echo ""
        echo "Blocked IPs:"
        nft list set inet $NFT_TABLE blocked_ips 2>/dev/null | grep -E "elements|timeout"
        echo ""
        echo "SSH Blocked:"
        nft list set inet $NFT_TABLE ssh_blocked 2>/dev/null | grep -E "elements|timeout"
    else
        echo "Status: Stopped"
    fi
}

unblock_ip() {
    local ip="$1"
    [ -n "$ip" ] || { echo "Usage: $0 unblock <ip>"; return 1; }
    
    nft delete element inet $NFT_TABLE blocked_ips { $ip } 2>/dev/null
    nft delete element inet $NFT_TABLE ssh_blocked { $ip } 2>/dev/null
    log "info" "Unblocked IP: $ip"
    echo "Unblocked: $ip"
}

case "$1" in
    start) start_ids ;;
    stop) stop_ids ;;
    restart) stop_ids; sleep 1; start_ids ;;
    reload) start_ids ;;
    status) status_ids ;;
    unblock) unblock_ip "$2" ;;
    *) echo "Usage: $0 {start|stop|restart|reload|status|unblock <ip>}" ;;
esac
