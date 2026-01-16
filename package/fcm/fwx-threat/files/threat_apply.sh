#!/bin/sh
# FWX Threat Intelligence Apply Script
# Apply blacklists to nftables using atomic ruleset loading

. /lib/functions.sh
. /lib/fwx/nft_atomic.sh 2>/dev/null || true

THREAT_DIR="/etc/fwx/threat"
IP_BLACKLIST="$THREAT_DIR/ip_blacklist.txt"
DOMAIN_BLACKLIST="$THREAT_DIR/domain_blacklist.txt"
NFT_TABLE="fwx_threat"
NFT_FILE="/tmp/fwx-threat.nft"

log() {
    logger -t fwx-threat "$1"
}

# 获取文件锁
acquire_lock() {
    if type nft_lock >/dev/null 2>&1; then
        nft_lock "$NFT_TABLE" 60
    else
        local timeout=60 i=0
        while [ $i -lt $timeout ]; do
            if mkdir "/tmp/fwx-threat.lock" 2>/dev/null; then
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
        rmdir "/tmp/fwx-threat.lock" 2>/dev/null
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
            \#*|"") continue ;;
        esac
        
        # Validate and categorize IP
        case "$ip" in
            *:*)
                # IPv6 - skip for now, handle separately
                continue
                ;;
            *.*.*.*/*)
                # IPv4 CIDR
                ;;
            *.*.*.*)
                # IPv4 single
                ;;
            *)
                continue
                ;;
        esac
        
        if [ $first -eq 1 ]; then
            printf "%s" "$ip"
            first=0
        else
            printf ", %s" "$ip"
        fi
        
        count=$((count + 1))
        
        # 换行避免行太长
        if [ $((count % batch_size)) -eq 0 ]; then
            printf ",\n            "
            first=1
        fi
    done < "$blacklist"
}

# 生成原子规则集
generate_ruleset() {
    local enable action log_blocked
    
    config_load threat_intel
    config_get enable global enable "0"
    config_get action global action "drop"
    config_get_bool log_blocked global log_blocked 1
    
    [ "$enable" = "1" ] || return 1
    
    [ -f "$IP_BLACKLIST" ] || {
        log "No IP blacklist found"
        return 1
    }
    
    local log_stmt=""
    [ "$log_blocked" = "1" ] && log_stmt='log prefix "[FWX-THREAT] " '
    
    # 开始生成规则集
    cat > "$NFT_FILE" <<EOF
# FWX Threat Intelligence Atomic Ruleset
# Auto-generated, do not edit manually

table inet $NFT_TABLE {
    set threat_ips {
        type ipv4_addr
        flags interval
EOF

    # 检查是否有 IP 需要添加
    local ip_count=$(grep -cvE '^#|^$' "$IP_BLACKLIST" 2>/dev/null || echo 0)
    
    if [ "$ip_count" -gt 0 ]; then
        echo "        elements = {" >> "$NFT_FILE"
        echo -n "            " >> "$NFT_FILE"
        generate_ip_elements "$IP_BLACKLIST" >> "$NFT_FILE"
        echo "" >> "$NFT_FILE"
        echo "        }" >> "$NFT_FILE"
    fi
    
    cat >> "$NFT_FILE" <<EOF
    }
    
    set threat_ips6 {
        type ipv6_addr
        flags interval
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

# 原子应用规则集（不打断现有连接）
apply_atomic() {
    # 使用公共库或直接加载
    if type nft_atomic_load >/dev/null 2>&1; then
        if nft_atomic_load "$NFT_FILE" "$NFT_TABLE"; then
            log "Ruleset applied atomically (via lib)"
            return 0
        fi
        return 1
    fi
    
    # Fallback: 直接原子加载
    nft delete table inet $NFT_TABLE 2>/dev/null
    if nft -f "$NFT_FILE" 2>/dev/null; then
        log "Ruleset applied atomically"
        return 0
    fi
    
    log "Failed to load new ruleset"
    return 1
}

# 热更新：增量更新 set 元素，不重建表结构
# 保留统计计数器，零中断
hot_update_ips() {
    local new_blacklist="$1"
    
    [ -f "$new_blacklist" ] || return 1
    
    # 检查表是否存在
    if ! nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        log "Table not exists, doing full apply"
        return 1  # 需要完整应用
    fi
    
    log "Starting hot update..."
    
    # 获取当前 set 中的 IP
    local current_ips="/tmp/fwx-threat-current.txt"
    local new_ips="/tmp/fwx-threat-new.txt"
    local to_add="/tmp/fwx-threat-add.txt"
    local to_del="/tmp/fwx-threat-del.txt"
    
    # 导出当前 IP
    nft list set inet $NFT_TABLE threat_ips 2>/dev/null | \
        grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' | \
        sort -u > "$current_ips"
    
    # 处理新 IP 列表
    grep -vE '^#|^$' "$new_blacklist" | sort -u > "$new_ips"
    
    # 计算差异
    comm -23 "$new_ips" "$current_ips" > "$to_add"  # 新增
    comm -13 "$new_ips" "$current_ips" > "$to_del"  # 删除
    
    local add_count=$(wc -l < "$to_add" 2>/dev/null || echo 0)
    local del_count=$(wc -l < "$to_del" 2>/dev/null || echo 0)
    
    log "Hot update: +$add_count -$del_count IPs"
    
    # 生成增量更新脚本
    local update_file="/tmp/fwx-threat-update.nft"
    : > "$update_file"
    
    # 批量删除
    if [ -s "$to_del" ]; then
        local batch=""
        local count=0
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            if [ -z "$batch" ]; then
                batch="$ip"
            else
                batch="$batch, $ip"
            fi
            count=$((count + 1))
            if [ $count -ge 500 ]; then
                echo "delete element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
                batch=""
                count=0
            fi
        done < "$to_del"
        [ -n "$batch" ] && echo "delete element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
    fi
    
    # 批量添加
    if [ -s "$to_add" ]; then
        local batch=""
        local count=0
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            if [ -z "$batch" ]; then
                batch="$ip"
            else
                batch="$batch, $ip"
            fi
            count=$((count + 1))
            if [ $count -ge 500 ]; then
                echo "add element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
                batch=""
                count=0
            fi
        done < "$to_add"
        [ -n "$batch" ] && echo "add element inet $NFT_TABLE threat_ips { $batch }" >> "$update_file"
    fi
    
    # 原子执行增量更新
    if [ -s "$update_file" ]; then
        if nft -f "$update_file" 2>/dev/null; then
            log "Hot update completed: +$add_count -$del_count"
        else
            log "Hot update failed, falling back to full apply"
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
    local enable
    
    config_load threat_intel
    config_get enable global enable "0"
    
    if [ "$enable" != "1" ]; then
        # Cleanup if disabled
        nft delete table inet $NFT_TABLE 2>/dev/null
        log "Threat protection disabled"
        return 0
    fi
    
    [ -f "$IP_BLACKLIST" ] || {
        log "No IP blacklist found"
        return 1
    }
    
    acquire_lock || return 1
    
    # 尝试热更新（增量更新，保留计数器）
    if hot_update_ips "$IP_BLACKLIST"; then
        release_lock
        return 0
    fi
    
    # 热更新失败，执行完整应用
    log "Performing full ruleset apply"
    if generate_ruleset; then
        apply_atomic
        local result=$?
        release_lock
        return $result
    else
        release_lock
        return 1
    fi
}

apply_domain_blacklist() {
    [ -f "$DOMAIN_BLACKLIST" ] || return 0
    
    # Domain blocking via dnsmasq
    local dnsmasq_conf="/tmp/dnsmasq.d/fwx-threat.conf"
    
    mkdir -p /tmp/dnsmasq.d
    
    {
        echo "# FWX Threat Intelligence - Blocked Domains"
        echo "# Auto-generated, do not edit"
        while IFS= read -r domain; do
            case "$domain" in
                \#*|"") continue ;;
            esac
            echo "address=/$domain/"
        done < "$DOMAIN_BLACKLIST"
    } > "$dnsmasq_conf"
    
    # Reload dnsmasq if running
    if pidof dnsmasq >/dev/null; then
        /etc/init.d/dnsmasq reload 2>/dev/null
        log "Applied domain blacklist to dnsmasq"
    fi
}

# 增量更新 IP（不重建整个表）
add_threat_ip() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        nft add element inet $NFT_TABLE threat_ips { "$ip" }
        log "Added threat IP: $ip"
    else
        log "Table not exists, run full apply first"
        return 1
    fi
}

remove_threat_ip() {
    local ip="$1"
    [ -n "$ip" ] || return 1
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        nft delete element inet $NFT_TABLE threat_ips { "$ip" }
        log "Removed threat IP: $ip"
    fi
}

status() {
    echo "=== FWX Threat Status ==="
    
    if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
        echo "Status: Active (atomic mode)"
        local count=$(nft list set inet $NFT_TABLE threat_ips 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l)
        echo "Blocked IPs: $count"
        echo ""
        echo "Chain statistics:"
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
    ip)
        apply_ip_blacklist
        ;;
    domain)
        apply_domain_blacklist
        ;;
    hot)
        # 强制热更新模式
        acquire_lock || exit 1
        if hot_update_ips "$IP_BLACKLIST"; then
            echo "Hot update successful"
        else
            echo "Hot update failed, use 'apply' for full rebuild"
        fi
        release_lock
        ;;
    add)
        add_threat_ip "$2"
        ;;
    remove)
        remove_threat_ip "$2"
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 [apply|ip|domain|hot|add <ip>|remove <ip>|status]"
        exit 1
        ;;
esac
