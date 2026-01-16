#!/bin/sh
# FWX Antivirus Manager
# ClamAV integration for FanchMWRT

. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CLAMSCAN="/usr/bin/clamscan"
CLAMDSCAN="/usr/bin/clamdscan"
FRESHCLAM="/usr/bin/freshclam"
CLAMD="/usr/sbin/clamd"
CLAMD_CONF="/etc/clamav/clamd.conf"
FRESHCLAM_CONF="/etc/clamav/freshclam.conf"

LOG_FILE="/tmp/log/fwx-av.log"
QUARANTINE_DIR="/etc/fwx/av/quarantine"
SCAN_REPORT="/tmp/fwx-av-report.txt"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    logger -t fwx-av "$1"
}

alert() {
    local type="$1"
    local file="$2"
    local virus="$3"
    
    log "ALERT: $type - File: $file, Threat: $virus"
    
    # Send to fwxd via ubus
    ubus call fwx alert "{\"type\":\"malware\",\"detail\":\"$virus in $file\"}" 2>/dev/null
    
    # Check email notification
    config_load fwx_av
    local email_enable email_to
    config_get email_enable action email_enable "0"
    config_get email_to action email_to ""
    
    if [ "$email_enable" = "1" ] && [ -n "$email_to" ]; then
        echo "FWX AV Alert: $virus detected in $file" | \
            sendmail "$email_to" 2>/dev/null
    fi
}

check_clamav() {
    if [ ! -x "$CLAMSCAN" ]; then
        log "ERROR: ClamAV not installed"
        echo "ClamAV not installed. Install with: opkg install clamav"
        return 1
    fi
    return 0
}

init_dirs() {
    mkdir -p "$QUARANTINE_DIR"
    mkdir -p "$(dirname $LOG_FILE)"
    chmod 700 "$QUARANTINE_DIR"
}

update_database() {
    check_clamav || return 1
    
    log "Updating ClamAV database..."
    
    if [ -x "$FRESHCLAM" ]; then
        $FRESHCLAM --quiet
        if [ $? -eq 0 ]; then
            log "Database updated successfully"
            return 0
        else
            log "ERROR: Database update failed"
            return 1
        fi
    else
        log "ERROR: freshclam not found"
        return 1
    fi
}

quarantine_file() {
    local file="$1"
    local virus="$2"
    
    if [ ! -f "$file" ]; then
        return 1
    fi
    
    local basename=$(basename "$file")
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local quarantine_name="${timestamp}_${basename}.infected"
    
    mv "$file" "$QUARANTINE_DIR/$quarantine_name"
    chmod 000 "$QUARANTINE_DIR/$quarantine_name"
    
    # Log quarantine info
    echo "$timestamp|$file|$virus|$quarantine_name" >> "$QUARANTINE_DIR/quarantine.log"
    
    log "Quarantined: $file -> $quarantine_name"
}

delete_file() {
    local file="$1"
    
    if [ -f "$file" ]; then
        rm -f "$file"
        log "Deleted infected file: $file"
    fi
}

handle_detection() {
    local file="$1"
    local virus="$2"
    
    config_load fwx_av
    local action
    config_get action action on_detect "quarantine"
    
    alert "malware" "$file" "$virus"
    
    case "$action" in
        quarantine)
            quarantine_file "$file" "$virus"
            ;;
        delete)
            delete_file "$file"
            ;;
        log)
            log "Detected (log only): $virus in $file"
            ;;
    esac
}

scan_file() {
    local file="$1"
    
    check_clamav || return 1
    
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        return 1
    fi
    
    log "Scanning file: $file"
    
    local result=$($CLAMSCAN --no-summary "$file" 2>&1)
    local status=$?
    
    if [ $status -eq 1 ]; then
        # Virus found
        local virus=$(echo "$result" | grep "FOUND" | awk -F: '{print $2}' | sed 's/ FOUND//')
        handle_detection "$file" "$virus"
        return 1
    elif [ $status -eq 0 ]; then
        log "Clean: $file"
        return 0
    else
        log "ERROR: Scan failed for $file"
        return 2
    fi
}

scan_directory() {
    local dir="$1"
    local recursive="${2:-1}"
    
    check_clamav || return 1
    
    if [ ! -d "$dir" ]; then
        echo "Directory not found: $dir"
        return 1
    fi
    
    log "Scanning directory: $dir"
    
    config_load fwx_av
    local max_size scan_archives
    config_get max_size scan max_file_size "25"
    config_get scan_archives scan scan_archives "1"
    
    local opts="--infected --no-summary"
    [ "$recursive" = "1" ] && opts="$opts -r"
    [ "$scan_archives" = "1" ] && opts="$opts --scan-archive"
    opts="$opts --max-filesize=${max_size}M"
    
    local infected=0
    local scanned=0
    
    # Run scan and process results
    $CLAMSCAN $opts "$dir" 2>&1 | while read line; do
        if echo "$line" | grep -q "FOUND"; then
            local file=$(echo "$line" | cut -d: -f1)
            local virus=$(echo "$line" | cut -d: -f2 | sed 's/ FOUND//')
            handle_detection "$file" "$virus"
            infected=$((infected + 1))
        fi
        scanned=$((scanned + 1))
    done
    
    log "Scan complete: $dir"
}

start_realtime() {
    config_load fwx_av
    local enable paths
    config_get enable scan realtime_enable "0"
    config_get paths scan realtime_paths ""
    
    if [ "$enable" != "1" ]; then
        log "Realtime scanning disabled"
        return 0
    fi
    
    if [ -z "$paths" ]; then
        log "No paths configured for realtime scanning"
        return 1
    fi
    
    log "Starting realtime monitoring for: $paths"
    
    # Use inotifywait if available
    if command -v inotifywait >/dev/null 2>&1; then
        for path in $paths; do
            if [ -d "$path" ]; then
                (
                    inotifywait -m -r -e create -e modify -e moved_to "$path" 2>/dev/null | \
                    while read dir event file; do
                        scan_file "${dir}${file}"
                    done
                ) &
                echo $! >> /tmp/fwx-av-realtime.pids
            fi
        done
        log "Realtime monitoring started"
    else
        log "WARNING: inotifywait not available, realtime scanning disabled"
        log "Install inotify-tools for realtime scanning"
    fi
}

stop_realtime() {
    if [ -f /tmp/fwx-av-realtime.pids ]; then
        while read pid; do
            kill "$pid" 2>/dev/null
        done < /tmp/fwx-av-realtime.pids
        rm -f /tmp/fwx-av-realtime.pids
    fi
    log "Realtime monitoring stopped"
}

list_quarantine() {
    echo "=== Quarantined Files ==="
    
    if [ -f "$QUARANTINE_DIR/quarantine.log" ]; then
        echo "Timestamp|Original Path|Threat|Quarantine Name"
        echo "---------|-------------|------|---------------"
        cat "$QUARANTINE_DIR/quarantine.log"
    else
        echo "No quarantined files"
    fi
}

restore_file() {
    local quarantine_name="$1"
    local restore_path="$2"
    
    local quarantine_file="$QUARANTINE_DIR/$quarantine_name"
    
    if [ ! -f "$quarantine_file" ]; then
        echo "Quarantine file not found: $quarantine_name"
        return 1
    fi
    
    if [ -z "$restore_path" ]; then
        # Get original path from log
        restore_path=$(grep "$quarantine_name" "$QUARANTINE_DIR/quarantine.log" | cut -d'|' -f2)
    fi
    
    if [ -z "$restore_path" ]; then
        echo "Cannot determine restore path"
        return 1
    fi
    
    chmod 644 "$quarantine_file"
    mv "$quarantine_file" "$restore_path"
    
    # Remove from log
    sed -i "/$quarantine_name/d" "$QUARANTINE_DIR/quarantine.log"
    
    log "Restored: $quarantine_name -> $restore_path"
    echo "Restored to: $restore_path"
}

status() {
    echo "=== FWX Antivirus Status ==="
    
    check_clamav
    local clamav_status=$?
    
    if [ $clamav_status -eq 0 ]; then
        echo "ClamAV: Installed"
        $CLAMSCAN --version 2>/dev/null | head -1
    else
        echo "ClamAV: Not installed"
    fi
    
    echo ""
    config_load fwx_av
    local enable realtime
    config_get enable global enable "0"
    config_get realtime scan realtime_enable "0"
    
    echo "FWX AV Enabled: $enable"
    echo "Realtime Scan: $realtime"
    
    if [ -f /tmp/fwx-av-realtime.pids ]; then
        echo "Realtime Monitor: Running"
    else
        echo "Realtime Monitor: Stopped"
    fi
    
    echo ""
    echo "Quarantine: $(ls -1 $QUARANTINE_DIR/*.infected 2>/dev/null | wc -l) files"
    
    # Database info
    if [ -d /var/lib/clamav ]; then
        echo ""
        echo "Database files:"
        ls -lh /var/lib/clamav/*.cvd 2>/dev/null | awk '{print "  " $NF ": " $5}'
    fi
}

case "$1" in
    scan)
        if [ -d "$2" ]; then
            scan_directory "$2" "${3:-1}"
        elif [ -f "$2" ]; then
            scan_file "$2"
        else
            echo "Usage: $0 scan <file|directory> [recursive:0|1]"
        fi
        ;;
    update)
        update_database
        ;;
    start-realtime)
        start_realtime
        ;;
    stop-realtime)
        stop_realtime
        ;;
    quarantine)
        list_quarantine
        ;;
    restore)
        restore_file "$2" "$3"
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {scan <path>|update|start-realtime|stop-realtime|quarantine|restore <name> [path]|status}"
        exit 1
        ;;
esac
