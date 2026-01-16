#!/bin/sh
# FWX Lightweight IDS
# Implements basic intrusion detection using nftables
# Uses atomic ruleset loading with temporary table strategy

. /lib/functions.sh
. /lib/fwx/nft_atomic.sh 2>/dev/null || true

NFT_TABLE="fwx_ids"
NFT_FILE="/tmp/fwx-ids.nft"
LOG_FILE="/tmp/log/fwx-ids.log"
BLOCKED_FILE="/tmp/fwx-ids-blocked.txt"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" >> "$LOG_FILE"
    logger -t fwx-ids -p "daemon.$1" "$2"
}

alert() {
    local type="$1"
    local src="$2"
    local detail="$3"
    
    log "warn" "ALERT: $type from $src - $detail"
    
    # Send to fwxd via ubus for unified handling
    ubus call fwx alert "{\"type\":\"$type\",\"src\":\"$src\",\"detail\":\"$detail\"}" 2>/dev/null
}

# 获取文件锁，防止并发操作
acquire_lock() {
    if type nft_lock >/dev/null 2>&1; then
        nft_lock "$NFT_TABLE" 30
    else
        # Fallback
        local timeout=30 i=0
        while [ $i -lt $timeout ]; do
            if mkdir "/tmp/fwx-ids.lock" 2>/dev/null; then
                trap 'release_lock' EXIT INT TERM
                return 0
            fi
            sleep 1
            i=$((i + 1))
        done
        return 1
    fi
}

release_lock() {
    if type nft_unlock >/dev/null 2>&1; then
        nft_unlock "$NFT_TABLE"
    else
        rmdir "/tmp/fwx-ids.lock" 2>/dev/null
    fi
}

# 导出现有 set 数据（保留已阻止的 IP）
export_existing_sets() {
    local sets_file="$1"
    
    if type nft_export_sets >/dev/null 2>&1; then
        nft_export_sets "$NFT_TABLE" "$sets_file"
    elif nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        {
            # 导出 blocked_ips
            echo "# Existing blocked IPs"
            nft list set inet $NFT_TABLE blocked_ips 2>/dev/null | \
                sed -n 's/.*elements = { \(.*\) }/\1/p' | tr ',' '\n' | \
                sed 's/^ *//' | grep -v '^$' | while read elem; do
                    echo "add element inet $NFT_TABLE blocked_ips { $elem }"
                done
            
            # 导出 ssh_blocked
            nft list set inet $NFT_TABLE ssh_blocked 2>/dev/null | \
                sed -n 's/.*elements = { \(.*\) }/\1/p' | tr ',' '\n' | \
                sed 's/^ *//' | grep -v '^$' | while read elem; do
                    echo "add element inet $NFT_TABLE ssh_blocked { $elem }"
                done
        } > "$sets_file"
    else
        : > "$sets_file"
    fi
}

# 生成原子规则集文件
generate_ruleset() {
    local enable threshold interval action block_time
    local rate burst ssh_enable ssh_max_retry ssh_block_time
    
    config_load fwx_ids
    config_get enable global enable "0"
    
    [ "$enable" = "1" ] || return 1
    
    cat > "$NFT_FILE" <<'NFTEOF'
# FWX IDS Atomic Ruleset
# Auto-generated, do not edit manually

NFTEOF

    # 创建新表
    cat >> "$NFT_FILE" <<EOF
table inet $NFT_TABLE_NEW {
    # Sets for tracking
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
    
    chain prerouting {
        type filter hook prerouting priority -200; policy accept;
    }
    
    chain input {
        type filter hook input priority -100; policy accept;
EOF

    # Port scan protection
    config_get enable portscan enable "0"
    if [ "$enable" = "1" ]; then
        config_get threshold portscan threshold "20"
        config_get interval portscan interval "60"
        config_get block_time portscan block_time "3600"
        
        log "info" "Enabling port scan protection (threshold: $threshold/${interval}s)"
        
        cat >> "$NFT_FILE" <<EOF
        
        # Port scan protection
        ip saddr @blocked_ips drop
        ct state new add @portscan_track { ip saddr . tcp dport timeout ${interval}s } limit rate over ${threshold}/minute add @blocked_ips { ip saddr timeout ${block_time}s } log prefix "[FWX-IDS:PORTSCAN] " drop
EOF
    fi

    # SYN flood protection
    config_get enable synflood enable "0"
    if [ "$enable" = "1" ]; then
        config_get rate synflood rate "25"
        config_get burst synflood burst "50"
        config_get action synflood action "drop"
        
        log "info" "Enabling SYN flood protection (rate: ${rate}/s, burst: $burst)"
        
        cat >> "$NFT_FILE" <<EOF
        
        # SYN flood protection
        tcp flags syn ct state new limit rate over ${rate}/second burst $burst packets log prefix "[FWX-IDS:SYNFLOOD] " $action
EOF
    fi

    # Brute force protection
    config_get enable bruteforce enable "0"
    if [ "$enable" = "1" ]; then
        config_get ssh_enable bruteforce ssh_enable "1"
        config_get ssh_max_retry bruteforce ssh_max_retry "5"
        config_get ssh_block_time bruteforce ssh_block_time "3600"
        
        if [ "$ssh_enable" = "1" ]; then
            log "info" "Enabling SSH brute force protection (max: $ssh_max_retry attempts)"
            
            cat >> "$NFT_FILE" <<EOF
        
        # SSH brute force protection
        ip saddr @ssh_blocked tcp dport 22 drop
        tcp dport 22 ct state new add @ssh_track { ip saddr timeout 60s limit rate over ${ssh_max_retry}/minute } add @ssh_blocked { ip saddr timeout ${ssh_block_time}s } log prefix "[FWX-IDS:SSH-BRUTE] " drop
EOF
        fi
    fi

    # ICMP flood protection
    config_get enable icmpflood enable "0"
    if [ "$enable" = "1" ]; then
        config_get rate icmpflood rate "10"
        config_get burst icmpflood burst "20"
        
        log "info" "Enabling ICMP flood protection (rate: ${rate}/s)"
        
        cat >> "$NFT_FILE" <<EOF
        
        # ICMP flood protection
        ip protocol icmp limit rate over ${rate}/second burst $burst packets log prefix "[FWX-IDS:ICMPFLOOD] " drop
EOF
    fi

    # 关闭 chain 和 table
    cat >> "$NFT_FILE" <<EOF
    }
}
EOF

    return 0
}

# 原子应用规则集
apply_atomic() {
    local sets_backup="/tmp/fwx-ids-sets.nft"
    
    # 导出现有 set 数据
    export_existing_sets "$sets_backup"
    
    # 使用公共库的原子替换（如果可用）
    if type nft_atomic_load >/dev/null 2>&1; then
        if nft_atomic_load "$NFT_FILE" "$NFT_TABLE"; then
            # 恢复 set 数据
            [ -s "$sets_backup" ] && nft -f "$sets_backup" 2>/dev/null
            log "info" "Ruleset applied atomically (via lib)"
            return 0
        else
            log "error" "Failed to apply ruleset"
            return 1
        fi
    fi
    
    # Fallback: 直接原子加载
    # 先删除旧表（如果存在）
    nft delete table inet $NFT_TABLE 2>/dev/null
    
    # 加载新规则集
    if nft -f "$NFT_FILE"; then
        # 恢复 set 数据
        [ -s "$sets_backup" ] && nft -f "$sets_backup" 2>/dev/null
        log "info" "Ruleset applied atomically"
        return 0
    else
        log "error" "Failed to apply ruleset"
        return 1
    fi
}

start_ids() {
    local enable
    
    config_load fwx_ids
    config_get enable global enable "0"
    
    [ "$enable" = "1" ] || {
        log "info" "FWX IDS disabled"
        return 0
    }
    
    log "info" "Starting FWX IDS (atomic mode)"
    
    acquire_lock || return 1
    
    if generate_ruleset; then
        if apply_atomic; then
            log "info" "FWX IDS started successfully"
        else
            log "error" "Failed to apply IDS rules"
            release_lock
            return 1
        fi
    else
        log "info" "No IDS rules to apply"
    fi
    
    release_lock
}

stop_ids() {
    log "info" "Stopping FWX IDS"
    acquire_lock || return 1
    nft delete table inet $NFT_TABLE 2>/dev/null
    nft delete table inet $NFT_TABLE_NEW 2>/dev/null
    release_lock
}

reload_ids() {
    log "info" "Reloading FWX IDS"
    start_ids
}

status_ids() {
    echo "=== FWX IDS Status ==="
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        echo "Status: Running (atomic mode)"
        echo ""
        echo "Blocked IPs:"
        nft list set inet $NFT_TABLE blocked_ips 2>/dev/null
        echo ""
        echo "SSH Blocked:"
        nft list set inet $NFT_TABLE ssh_blocked 2>/dev/null
        echo ""
        echo "Statistics:"
        nft list chain inet $NFT_TABLE input 2>/dev/null | grep -E "counter|packets"
    else
        echo "Status: Stopped"
    fi
}

unblock_ip() {
    local ip="$1"
    [ -n "$ip" ] || {
        echo "Usage: $0 unblock <ip>"
        return 1
    }
    
    nft delete element inet $NFT_TABLE blocked_ips { $ip } 2>/dev/null
    nft delete element inet $NFT_TABLE ssh_blocked { $ip } 2>/dev/null
    log "info" "Unblocked IP: $ip"
    echo "Unblocked: $ip"
}

case "$1" in
    start)
        start_ids
        ;;
    stop)
        stop_ids
        ;;
    restart)
        stop_ids
        sleep 1
        start_ids
        ;;
    reload)
        reload_ids
        ;;
    status)
        status_ids
        ;;
    unblock)
        unblock_ip "$2"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status|unblock <ip>}"
        exit 1
        ;;
esac
