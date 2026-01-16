#!/bin/sh
# FWX Threat Intelligence Apply Script
# Apply blacklists to nftables using atomic ruleset loading

. /lib/functions.sh
. /lib/fwx/nft_atomic.sh 2>/dev/null || true
. /lib/fwx/common.sh 2>/dev/null || true

THREAT_DIR="/etc/fwx/threat"
IP_BLACKLIST="$THREAT_DIR/ip_blacklist.txt"
DOMAIN_BLACKLIST="$THREAT_DIR/domain_blacklist.txt"
NFT_TABLE="fwx_threat"
NFT_FILE="/tmp/fwx-threat.nft"
LOG_TAG="fwx-threat"

log() {
    if type fwx_log >/dev/null 2>&1; then
        fwx_log "$LOG_TAG" "info" "$1"
    else
        logger -t "$LOG_TAG" "$1"
    fi
}

acquire_lock() {
    if type fwx_lock >/dev/null 2>&1; then
        fwx_lock "$NFT_TABLE" 60
    elif type nft_lock >/dev/null 2>&1; then
        nft_lock "$NFT_TABLE" 60
    else
        local timeout=60 i=0
        while [ $i -lt $timeout ]; do
            if mkdir "/tmp/fwx-threat.lock" 2>/dev/null; then
                echo $$ > "/tmp/fwx-threat.lock/pid"
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
        rm -rf "/tmp/fwx-threat.lock"
    fi
}

# 生成 IP 元素列表
generate_ip_elements() {
    local blacklist="$1"
    local batch_size=500
    local count=0
    local first=1
    
    while IFS= read -r ip || [ -n "$ip" ]; do
        # Skip comments and empty lines
        case "$ip" in
            \#*|""|" "*) continue ;;
        esac
        
        # Validate IPv4
        echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$' || continue
        
        if [ $first -eq 1 ]; then
            printf "%s" "$ip"
            first=0
        else
            printf ", %s" "$ip"
        fi
        
        count=$((count + 1))
        if [ $((count % batch_size)) -eq 0 ]; then
            printf ",\n            "
            first=1
        fi
    done < "$blacklist"
}

generate_ruleset() {
    local enable action log_blocked
    
    config_load threat_intel
    config_get enable global enable "0"
    config_get action global action "drop"
    config_get_bool log_blocked global log_blocked 1
    
    [ "$enable" = "1" ] || return 1
    [ -f "$IP_BLACKLIST" ] || { log "No IP blacklist found"; return 1; }
    
    local log_stmt=""
    [ "$log_blocked" = "1" ] && log_stmt='log prefix "[FWX-THREAT] " '
    
    # Count valid IPs
    local ip_count=$(grep -cvE '^#|^$|^ ' "$IP_BLACKLIST" 2>/dev/null || echo 0)
    
    cat > "$NFT_FILE" <<EOF
# FWX Threat Intelligence Atomic Ruleset
table inet $NFT_TABLE {
    set threat_ips {
        type ipv4_addr
        flags interval
EOF

    if [ "$ip_count" -gt 0 ]; then
        echo "        elements = {" >> "$NFT_FILE"
        echo -n "            " >> "$NFT_FILE"
        generate_ip_elements "$IP_BLACKLIST" >> "$NFT_FILE"
        echo "" >> "$NFT_FILE"
        echo "        }" >> "$NFT_FILE"
    fi
    
    cat >> "$NFT_FILE" <<EOF
    }
    
    chain input {
        type filter hook input priority -150; policy accept;
        ip saddr @threat_ips ${log_stmt}counter $action
        ip daddr @threat_ips ${log_stmt}counter $action
    }
    
    chain forward {
        type filter hook forward priority -150; policy accept;
        ip saddr @threat_ips ${log_stmt}counter $action
        ip daddr @threat_ips ${log_stmt}counter $action
    }
    
    chain output {
        type filter hook output priority -150; policy accept;
        ip daddr @threat_ips ${log_stmt}counter $action
    }
}
EOF

    log "Generated ruleset with $ip_count IPs"
    return 0
}

apply_atomic() {
    nft delete table inet $NFT_TABLE 2>/dev/null
    if nft -f "$NFT_FILE" 2>/dev/null; then
        log "Ruleset applied atomically"
        return 0
    fi
    log "Failed to load ruleset"
    return 1
}

# 热更新：增量更新 set 元素
hot_update_ips() {
    local new_blacklist="$1"
    [ -f "$new_blacklist" ] || return 1
    
    nft list table inet $NFT_TABLE >/dev/null 2>&1 || {
        log "Table not exists, doing full apply"
        return 1
    }
    
    log "Starting hot update..."
    
    local current_ips="/tmp/fwx-threat-current.txt"
    local new_ips="/tmp/fwx-threat-new.txt"
    local to_add="/tmp/fwx-threat-add.txt"
    local to_del="/tmp/fwx-threat-del.txt"
    
    # Export current IPs
    nft list set inet $NFT_TABLE threat_ips 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
        sort -u > "$current_ips"
    
    # Process new IP list
    grep -vE '^#|^$|^ ' "$new_blacklist" | sort -u > "$new_ips"
    
    # Calculate diff
    comm -23 "$new_ips" "$current_ips" > "$to_add"
    comm -13 "$new_ips" "$current_ips" > "$to_del"
    
    local add_count=$(wc -l < "$to_add" 2>/dev/null || echo 0)
    local del_count=$(wc -l < "$to_del" 2>/dev/null || echo 0)
    
    log "Hot update: +$add_count -$del_count IPs"
    
    local update_file="/tmp/fwx-threat-update.nft"
    : > "$update_file"
    
    # Batch delete
    if [ -s "$to_del" ]; then
        local batch="" count=0
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            batch="${batch:+$batch, }$ip"
            count=$((count + 1))
            if [ $count -ge 500 ]; then
                echo "delete element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
                batch="" count=0
            fi
        done < "$to_del"
        [ -n "$batch" ] && echo "delete element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
    fi
    
    # Batch add
    if [ -s "$to_add" ]; then
        local batch="" count=0
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            batch="${batch:+$batch, }$ip"
            count=$((count + 1))
            if [ $count -ge 500 ]; then
                echo "add element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
                batch="" count=0
            fi
        done < "$to_add"
        [ -n "$batch" ] && echo "add element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
    fi
    
    # Execute update
    if [ -s "$update_file" ]; then
        if nft -f "$update_file" 2>/dev/null; then
            log "Hot update completed: +$add_count -$del_count"
        else
            log "Hot update failed"
            rm -f "$current_ips" "$new_ips" "$to_add" "$to_del" "$update_file"
            return 1
        fi
    else
        log "No changes needed"
    fi
    
    rm -f "$current_ips" "$new_ips" "$to_add" "$to_del" "$update_file"
    return 0
}

apply_ip_blacklist() {
    config_load threat_intel
    local enable
    config_get enable global enable "0"
    
    if [ "$enable" != "1" ]; then
        nft delete table inet $NFT_TABLE 2>/dev/null
        log "Threat protection disabled"
        return 0
    fi
    
    [ -f "$IP_BLACKLIST" ] || { log "No IP blacklist found"; return 1; }
    
    acquire_lock || return 1
    
    # Try hot update first
    if hot_update_ips "$IP_BLACKLIST"; then
        release_lock
        return 0
    fi
    
    # Full apply
    log "Performing full ruleset apply"
    if generate_ruleset; then
        apply_atomic
        local ret=$?
        release_lock
        return $ret
    fi
    
    release_lock
    return 1
}

apply_domain_blacklist() {
    [ -f "$DOMAIN_BLACKLIST" ] || return 0
    
    local dnsmasq_conf="/tmp/dnsmasq.d/fwx-threat.conf"
    mkdir -p /tmp/dnsmasq.d
    
    {
        echo "# FWX Threat Intelligence - Blocked Domains"
        while IFS= read -r domain; do
            case "$domain" in \#*|"") continue ;; esac
            echo "address=/$domain/"
        done < "$DOMAIN_BLACKLIST"
    } > "$dnsmasq_conf"
    
    pidof dnsmasq >/dev/null && /etc/init.d/dnsmasq reload 2>/dev/null
    log "Applied domain blacklist"
}

add_threat_ip() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        nft add element inet $NFT_TABLE threat_ips { "$ip" }
        log "Added threat IP: $ip"
    else
        log "Table not exists"
        return 1
    fi
}

remove_threat_ip() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    
    nft delete element inet $NFT_TABLE threat_ips { "$ip" } 2>/dev/null
    log "Removed threat IP: $ip"
}

status() {
    echo "=== FWX Threat Status ==="
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        echo "Status: Active"
        local count=$(nft list set inet $NFT_TABLE threat_ips 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
        echo "Blocked IPs: $count"
        echo ""
        echo "Statistics:"
        nft list chain inet $NFT_TABLE input 2>/dev/null | grep -E "counter"
    else
        echo "Status: Inactive"
    fi
}

case "$1" in
    ""|apply)
        apply_ip_blacklist
        apply_domain_blacklist
        ;;
    ip) apply_ip_blacklist ;;
    domain) apply_domain_blacklist ;;
    hot)
        acquire_lock || exit 1
        hot_update_ips "$IP_BLACKLIST" && echo "Hot update successful" || echo "Hot update failed"
        release_lock
        ;;
    add) add_threat_ip "$2" ;;
    remove) remove_threat_ip "$2" ;;
    status) status ;;
    *) echo "Usage: $0 [apply|ip|domain|hot|add <ip>|remove <ip>|status]" ;;
esac
