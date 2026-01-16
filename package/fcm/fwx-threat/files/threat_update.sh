#!/bin/sh
# FWX Threat Intelligence Update Script
# Copyright (c) 2026 FanchMWRT

. /lib/functions.sh

THREAT_DIR="/etc/fwx/threat"
TEMP_DIR="/tmp/fwx-threat"
LOG_FILE="/tmp/log/fwx-threat.log"
IP_BLACKLIST="$THREAT_DIR/ip_blacklist.txt"
DOMAIN_BLACKLIST="$THREAT_DIR/domain_blacklist.txt"
LOCK_FILE="/tmp/fwx-threat-update.lock"

# 确保目录存在
mkdir -p "$THREAT_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    logger -t fwx-threat "$1"
}

# 获取锁，防止并发更新
acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log "ERROR: Another update is running (PID: $pid)"
            return 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
    return 0
}

release_lock() {
    rm -f "$LOCK_FILE"
}

# 下载并解析威胁源
download_source() {
    local name="$1"
    local url="$2"
    local type="$3"
    local format="$4"
    local output="$TEMP_DIR/${name}.tmp"
    
    log "Downloading $name from $url"
    
    # 使用curl下载，设置超时和重试
    if ! curl -s -f -L \
        --connect-timeout 30 \
        --max-time 120 \
        --retry 2 \
        --retry-delay 5 \
        -A "FanchMWRT-ThreatIntel/1.0" \
        -o "$output" "$url" 2>/dev/null; then
        log "ERROR: Failed to download $name"
        return 1
    fi
    
    # 检查文件是否有效
    if [ ! -s "$output" ]; then
        log "ERROR: Downloaded file is empty: $name"
        rm -f "$output"
        return 1
    fi
    
    # 根据格式解析
    case "$format" in
        plain)
            # 纯文本格式，每行一个IP或域名
            grep -v '^#' "$output" | \
            grep -v '^$' | \
            grep -v '^;' | \
            sed 's/\r$//' | \
            awk '{print $1}'
            ;;
        hosts)
            # hosts文件格式: 0.0.0.0 domain.com 或 127.0.0.1 domain.com
            grep -v '^#' "$output" | \
            grep -v '^$' | \
            sed 's/\r$//' | \
            awk '{print $2}' | \
            grep -v '^$' | \
            grep -v 'localhost'
            ;;
        spamhaus)
            # Spamhaus DROP格式: IP/CIDR ; SBL号
            grep -v '^;' "$output" | \
            grep -v '^$' | \
            sed 's/\r$//' | \
            awk '{print $1}' | \
            grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
            ;;
        csv)
            # CSV格式，第一列是IP或域名
            grep -v '^#' "$output" | \
            grep -v '^$' | \
            sed 's/\r$//' | \
            cut -d',' -f1 | \
            grep -v '^$'
            ;;
        json)
            # JSON格式，尝试提取IP字段
            if command -v jq >/dev/null 2>&1; then
                jq -r '.[] | .ip // .ioc // .indicator' "$output" 2>/dev/null | grep -v null
            else
                # 简单的grep提取
                grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$output"
            fi
            ;;
        *)
            cat "$output"
            ;;
    esac
    
    rm -f "$output"
    return 0
}

# 处理单个威胁源
process_source() {
    local section="$1"
    local enable name type url format
    
    config_get enable "$section" enable "0"
    [ "$enable" = "1" ] || return 0
    
    config_get name "$section" name "$section"
    config_get type "$section" type "ip"
    config_get url "$section" url ""
    config_get format "$section" format "plain"
    
    [ -n "$url" ] || {
        log "WARNING: No URL for source $name"
        return 0
    }
    
    local output
    if [ "$type" = "ip" ]; then
        output="$TEMP_DIR/ip_list.txt"
    else
        output="$TEMP_DIR/domain_list.txt"
    fi
    
    download_source "$name" "$url" "$type" "$format" >> "$output" 2>/dev/null
    local ret=$?
    
    if [ $ret -eq 0 ]; then
        log "SUCCESS: Processed $name"
    else
        log "WARNING: Failed to process $name"
    fi
    
    return $ret
}

# 应用白名单过滤
apply_whitelist() {
    local list_file="$1"
    local whitelist_type="$2"
    
    [ -f "$list_file" ] || return 0
    
    # 获取白名单
    local whitelist=""
    config_list_foreach whitelist "$whitelist_type" _collect_whitelist
    
    if [ -n "$whitelist" ]; then
        local temp_file="${list_file}.filtered"
        grep -v -F -f <(echo "$whitelist" | tr ' ' '\n') "$list_file" > "$temp_file" 2>/dev/null
        mv "$temp_file" "$list_file"
    fi
}

_collect_whitelist() {
    whitelist="$whitelist $1"
}

# 验证IP格式
validate_ip() {
    echo "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'
}

# 验证域名格式
validate_domain() {
    echo "$1" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
}

# 清理和验证列表
cleanup_list() {
    local input="$1"
    local output="$2"
    local type="$3"
    
    [ -f "$input" ] || return 1
    
    local valid_count=0
    local invalid_count=0
    
    while IFS= read -r line; do
        # 跳过空行和注释
        case "$line" in
            ""|\#*|";;"*) continue ;;
        esac
        
        # 去除空白
        line=$(echo "$line" | tr -d ' \t\r')
        
        # 验证格式
        if [ "$type" = "ip" ]; then
            if validate_ip "$line"; then
                echo "$line"
                valid_count=$((valid_count + 1))
            else
                invalid_count=$((invalid_count + 1))
            fi
        else
            if validate_domain "$line"; then
                echo "$line"
                valid_count=$((valid_count + 1))
            else
                invalid_count=$((invalid_count + 1))
            fi
        fi
    done < "$input" | sort -u > "$output"
    
    log "Validated $type list: $valid_count valid, $invalid_count invalid"
}

# 主更新函数
update_lists() {
    acquire_lock || return 1
    trap release_lock EXIT
    
    log "=========================================="
    log "Starting threat intelligence update"
    
    # 创建临时目录
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    touch "$TEMP_DIR/ip_list.txt" "$TEMP_DIR/domain_list.txt"
    
    # 加载配置并处理所有源
    config_load threat_intel
    
    local success_count=0
    local fail_count=0
    
    # 处理每个源
    config_foreach process_source source
    
    # 清理和验证IP列表
    if [ -s "$TEMP_DIR/ip_list.txt" ]; then
        cleanup_list "$TEMP_DIR/ip_list.txt" "$IP_BLACKLIST.new" "ip"
        
        if [ -s "$IP_BLACKLIST.new" ]; then
            local ip_count=$(wc -l < "$IP_BLACKLIST.new")
            
            # 备份旧文件
            [ -f "$IP_BLACKLIST" ] && cp "$IP_BLACKLIST" "$IP_BLACKLIST.bak"
            
            mv "$IP_BLACKLIST.new" "$IP_BLACKLIST"
            log "Updated IP blacklist: $ip_count entries"
        else
            log "WARNING: No valid IPs after cleanup"
        fi
    else
        log "WARNING: No IP data downloaded"
    fi
    
    # 清理和验证域名列表
    if [ -s "$TEMP_DIR/domain_list.txt" ]; then
        cleanup_list "$TEMP_DIR/domain_list.txt" "$DOMAIN_BLACKLIST.new" "domain"
        
        if [ -s "$DOMAIN_BLACKLIST.new" ]; then
            local domain_count=$(wc -l < "$DOMAIN_BLACKLIST.new")
            
            # 备份旧文件
            [ -f "$DOMAIN_BLACKLIST" ] && cp "$DOMAIN_BLACKLIST" "$DOMAIN_BLACKLIST.bak"
            
            mv "$DOMAIN_BLACKLIST.new" "$DOMAIN_BLACKLIST"
            log "Updated domain blacklist: $domain_count entries"
        else
            log "WARNING: No valid domains after cleanup"
        fi
    else
        log "WARNING: No domain data downloaded"
    fi
    
    # 清理临时文件
    rm -rf "$TEMP_DIR"
    
    # 应用规则（优先热更新）
    log "Applying threat rules..."
    if [ -x /usr/bin/fwx-threat-apply ]; then
        # 先尝试热更新，失败则完整应用
        /usr/bin/fwx-threat-apply hot 2>/dev/null || /usr/bin/fwx-threat-apply
        log "Threat rules applied"
    else
        log "WARNING: fwx-threat-apply not found"
    fi
    
    # 记录更新时间
    date +%s > "$THREAT_DIR/.last_update"
    
    log "Threat intelligence update completed"
    log "=========================================="
    
    release_lock
    trap - EXIT
}

# 显示状态
show_status() {
    echo "=== FWX Threat Intelligence Status ==="
    
    if [ -f "$IP_BLACKLIST" ]; then
        echo "IP Blacklist: $(wc -l < "$IP_BLACKLIST") entries"
    else
        echo "IP Blacklist: Not found"
    fi
    
    if [ -f "$DOMAIN_BLACKLIST" ]; then
        echo "Domain Blacklist: $(wc -l < "$DOMAIN_BLACKLIST") entries"
    else
        echo "Domain Blacklist: Not found"
    fi
    
    if [ -f "$THREAT_DIR/.last_update" ]; then
        local last=$(cat "$THREAT_DIR/.last_update")
        local now=$(date +%s)
        local age=$(( (now - last) / 3600 ))
        echo "Last Update: $(date -d "@$last" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$last" '+%Y-%m-%d %H:%M:%S') ($age hours ago)"
    else
        echo "Last Update: Never"
    fi
    
    echo ""
    echo "NFTables Status:"
    if nft list table inet fwx_threat >/dev/null 2>&1; then
        echo "  Table: Active"
        local blocked=$(nft list table inet fwx_threat 2>/dev/null | grep -c "counter packets")
        echo "  Rules: $blocked"
    else
        echo "  Table: Not loaded"
    fi
}

# 使用说明
usage() {
    cat <<EOF
FWX Threat Intelligence Update Script

Usage: $0 <command>

Commands:
  update    Download and apply threat intelligence
  status    Show current status
  help      Show this help

Examples:
  $0 update     # Update all threat lists
  $0 status     # Show status

Configuration: /etc/config/threat_intel
EOF
    exit 0
}

# 主入口
case "$1" in
    update)
        update_lists
        ;;
    status)
        show_status
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        echo "Usage: $0 {update|status|help}"
        exit 1
        ;;
esac
