#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_audit"
LOG_DIR="/var/log/fwx"

start_audit() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 1
    [ "$enable" != "1" ] && return 0
    
    mkdir -p "$LOG_DIR"
    logger -t fwx-audit "Audit logging started"
}

stop_audit() {
    logger -t fwx-audit "Audit logging stopped"
}

view_log() {
    local category="${1:-all}"
    local lines="${2:-50}"
    tail -n "$lines" "$LOG_DIR/${category}.log" 2>/dev/null || tail -n "$lines" /var/log/messages
}

export_logs() {
    local output="${1:-/tmp/fwx-audit-export.tar.gz}"
    tar -czf "$output" -C "$LOG_DIR" . 2>/dev/null
    echo "Exported to: $output"
}

case "$1" in
    start) start_audit ;;
    stop) stop_audit ;;
    restart) stop_audit; start_audit ;;
    view) view_log "$2" "$3" ;;
    export) export_logs "$2" ;;
    *) echo "Usage: $0 {start|stop|restart|view|export}" ;;
esac
