#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_reports"
REPORT_DIR="/www/fwx/reports"

generate_stats() {
    mkdir -p "$REPORT_DIR"
    local now=$(date +%s)
    local wan_dev=$(ip route | grep default | awk '{print $5}' | head -1)
    local rx=0 tx=0
    
    [ -n "$wan_dev" ] && [ -d "/sys/class/net/$wan_dev" ] && {
        rx=$(cat /sys/class/net/$wan_dev/statistics/rx_bytes 2>/dev/null || echo 0)
        tx=$(cat /sys/class/net/$wan_dev/statistics/tx_bytes 2>/dev/null || echo 0)
    }
    
    local conns=$(cat /proc/net/nf_conntrack 2>/dev/null | wc -l || echo 0)
    local blocked=$(nft list set inet fwx_threat blocked_ips 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | wc -l || echo 0)
    
    cat > "$REPORT_DIR/stats.json" << EOF
{"timestamp":$now,"traffic":{"rx":$rx,"tx":$tx},"connections":$conns,"blocked":$blocked}
EOF
}

start_reports() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 1
    [ "$enable" != "1" ] && return 0
    
    generate_stats
    logger -t fwx-reports "Reports started"
}

case "$1" in
    start) start_reports ;;
    stop) logger -t fwx-reports "Reports stopped" ;;
    restart) start_reports ;;
    generate) generate_stats ;;
    *) echo "Usage: $0 {start|stop|restart|generate}" ;;
esac
