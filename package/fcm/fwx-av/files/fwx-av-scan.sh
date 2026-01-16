#!/bin/sh
# FWX AV Quick Scan Script
# For scheduled scanning via cron

. /lib/functions.sh

LOG_FILE="/tmp/log/fwx-av.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SCHEDULED] $1" >> "$LOG_FILE"
    logger -t fwx-av-scan "$1"
}

config_load fwx_av

enable=""
scan_path=""
config_get enable schedule enable "0"
config_get scan_path schedule scan_path "/tmp"

if [ "$enable" != "1" ]; then
    exit 0
fi

log "Starting scheduled scan: $scan_path"

/usr/bin/fwx-av scan "$scan_path" 1

log "Scheduled scan completed"
