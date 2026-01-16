#!/bin/sh
# FWX Deep Packet Inspection Module
# nDPI integration for application identification

. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_dpi"
LOG_TAG="fwx-dpi"
STATS_FILE="/tmp/fwx-dpi-stats.json"
NDPI_PROC="/proc/net/xt_ndpi"

log() {
    if type fwx_log >/dev/null 2>&1; then
        fwx_log "$LOG_TAG" "info" "$1"
    else
        logger -t "$LOG_TAG" "$1"
    fi
}

# 检查 nDPI 内核模块
check_ndpi() {
    if [ ! -d "$NDPI_PROC" ]; then
        log "nDPI kernel module not loaded"
        modprobe xt_ndpi 2>/dev/null || {
            log "Failed to load xt_ndpi module"
            return 1
        }
    fi
    return 0
}

# 获取 nDPI 支持的协议列表
list_protocols() {
    if [ -f "$NDPI_PROC/proto" ]; then
        cat "$NDPI_PROC/proto"
    else
        # 常见协议列表
        echo "http https dns ssh ftp smtp pop3 imap"
        echo "facebook youtube netflix tiktok wechat"
        echo "bittorrent steam zoom teams slack"
    fi
}

# 应用 nDPI 规则
apply_category() {
    local section="$1"
    local name action mark priority
    local apps=""
    
    config_get name "$section" name ""
    config_get action "$section" action "accept"
    config_get mark "$section" mark ""
    config_get priority "$section" priority ""
    
    # 收集应用列表
    config_list_foreach "$section" apps _collect_app
    
    [ -z "$apps" ] && return 0
    
    log "Applying category: $name ($action)"
    
    for app in $apps; do
        case "$action" in
            drop)
                iptables -A FORWARD -m ndpi --$app -j DROP 2>/dev/null
                [ "$log_enable" = "1" ] && \
                    iptables -A FORWARD -m ndpi --$app -j LOG --log-prefix "[FWX-DPI:$app] " 2>/dev/null
                ;;
            mark)
                [ -n "$mark" ] && \
                    iptables -t mangle -A FORWARD -m ndpi --$app -j MARK --set-mark $mark 2>/dev/null
                ;;
            accept)
                iptables -A FORWARD -m ndpi --$app -j ACCEPT 2>/dev/null
                ;;
        esac
    done
}

_collect_app() {
    apps="$apps $1"
}

# 应用自定义规则
apply_rule() {
    local section="$1"
    local name action log_rule
    local apps=""
    
    config_get name "$section" name ""
    config_get action "$section" action "accept"
    config_get_bool log_rule "$section" log 0
    
    config_list_foreach "$section" apps _collect_app
    
    [ -z "$apps" ] && return 0
    
    log "Applying rule: $name ($action)"
    
    for app in $apps; do
        [ "$log_rule" = "1" ] && \
            iptables -A FORWARD -m ndpi --$app -j LOG --log-prefix "[FWX-DPI:$name] " 2>/dev/null
        
        case "$action" in
            drop)
                iptables -A FORWARD -m ndpi --$app -j DROP 2>/dev/null
                ;;
            accept)
                iptables -A FORWARD -m ndpi --$app -j ACCEPT 2>/dev/null
                ;;
        esac
    done
}

# 生成统计信息
generate_stats() {
    local stats_file="$1"
    
    if [ -f "$NDPI_PROC/stats" ]; then
        # 从内核读取统计
        cat "$NDPI_PROC/stats" > "$stats_file"
    else
        # 从 iptables 计数器读取
        {
            echo "{"
            echo "  \"timestamp\": $(date +%s),"
            echo "  \"protocols\": {"
            
            local first=1
            iptables -L FORWARD -v -n 2>/dev/null | grep "ndpi" | while read line; do
                local pkts=$(echo "$line" | awk '{print $1}')
                local bytes=$(echo "$line" | awk '{print $2}')
                local proto=$(echo "$line" | grep -oE '\-\-[a-z]+' | sed 's/--//')
                
                [ -z "$proto" ] && continue
                
                [ $first -eq 0 ] && echo ","
                first=0
                echo "    \"$proto\": {\"packets\": $pkts, \"bytes\": $bytes}"
            done
            
            echo "  }"
            echo "}"
        } > "$stats_file"
    fi
}

# 启动 DPI
start_dpi() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    
    [ "$enable" != "1" ] && {
        log "DPI disabled"
        return 0
    }
    
    check_ndpi || return 1
    
    log "Starting DPI"
    
    # 清理旧规则
    iptables -F FORWARD 2>/dev/null
    iptables -t mangle -F FORWARD 2>/dev/null
    
    # 获取日志设置
    local log_enable
    config_get_bool log_enable global log_enable 1
    
    # 应用分类策略
    config_foreach apply_category category
    
    # 应用自定义规则
    config_foreach apply_rule rule
    
    # 启动统计收集
    local stats_enable stats_interval
    config_get_bool stats_enable global stats_enable 1
    config_get stats_interval global stats_interval 60
    
    if [ "$stats_enable" = "1" ]; then
        start_stats_collector "$stats_interval" &
    fi
    
    log "DPI started"
}

# 停止 DPI
stop_dpi() {
    log "Stopping DPI"
    
    # 清理规则
    iptables -F FORWARD 2>/dev/null
    iptables -t mangle -F FORWARD 2>/dev/null
    
    # 停止统计收集
    killall -q fwx-dpi-stats 2>/dev/null
    
    log "DPI stopped"
}

# 统计收集器
start_stats_collector() {
    local interval="${1:-60}"
    
    while true; do
        generate_stats "$STATS_FILE"
        sleep "$interval"
    done
}

# 显示状态
status_dpi() {
    echo "=== FWX DPI Status ==="
    
    if [ -d "$NDPI_PROC" ]; then
        echo "nDPI Module: Loaded"
    else
        echo "nDPI Module: Not loaded"
    fi
    
    echo ""
    echo "Active Rules:"
    iptables -L FORWARD -v -n 2>/dev/null | grep -E "ndpi|LOG" | head -20
    
    echo ""
    echo "Mangle Rules:"
    iptables -t mangle -L FORWARD -v -n 2>/dev/null | grep "ndpi" | head -10
    
    if [ -f "$STATS_FILE" ]; then
        echo ""
        echo "Statistics:"
        cat "$STATS_FILE"
    fi
}

# 获取统计
get_stats() {
    if [ -f "$STATS_FILE" ]; then
        cat "$STATS_FILE"
    else
        echo '{"error": "No stats available"}'
    fi
}

# 实时流量监控
monitor() {
    local interval="${1:-2}"
    
    echo "Monitoring DPI traffic (Ctrl+C to stop)..."
    echo ""
    
    while true; do
        clear
        echo "=== FWX DPI Monitor === $(date)"
        echo ""
        iptables -L FORWARD -v -n 2>/dev/null | grep "ndpi" | \
            awk '{printf "%-20s %10s pkts %10s bytes\n", $NF, $1, $2}'
        sleep "$interval"
    done
}

case "$1" in
    start) start_dpi ;;
    stop) stop_dpi ;;
    restart) stop_dpi; sleep 1; start_dpi ;;
    status) status_dpi ;;
    stats) get_stats ;;
    monitor) monitor "$2" ;;
    protocols) list_protocols ;;
    *) echo "Usage: $0 {start|stop|restart|status|stats|monitor|protocols}" ;;
esac
