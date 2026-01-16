#!/bin/sh
# FWX Threat Intelligence Update Script

. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

THREAT_DIR="/etc/fwx/threat"
TEMP_DIR="/tmp/fwx-threat"
LOG_FILE="/tmp/log/fwx-threat.log"
IP_BLACKLIST="$THREAT_DIR/ip_blacklist.txt"
DOMAIN_BLACKLIST="$THREAT_DIR/domain_blacklist.txt"
LOCK_FILE="/tmp/fwx-threat-update.lock"
LOG_TAG="fwx-threat"

mkdir -p "$THREAT_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    logger -t "$LOG_TAG" "$1"
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            log "ERROR: Another update running (PID: $pid)"
            return 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
    return 0
}

release_lock() {
    rm -f "$LOCK_FILE"
}

download_source() {
    local name="$1" url="$2" type="$3" format="$4"
    local output="$TEMP_DIR/${name}.tmp"
    
    log "Downloading $name"
    
    if ! curl -s -f -L --connect-timeout 30 --max-time 120 --retry 2 \
        -A "FanchMWRT-ThreatIntel/1.0" -o "$output" "$url" 2>/dev/null; then
        log "ERROR: Failed to download $name"
        return 1
    fi
    
    [ -s "$output" ] || { log "ERROR: Empty file: $name"; rm -f "$output"; return 1; }
    
    case "$format" in
        plain)
            grep -vE '^#|^$|^;' "$output" | sed 's/\r$//' | awk '{print $1}'
            ;;
        hosts)
            grep -vE '^#|^$' "$output" | sed 's/\r$//' | awk '{print $2}' | grep -vE '^$|localhost'
            ;;
        spamhaus)
            grep -vE '^;|^$' "$output" | sed 's/\r$//' | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
            ;;
        csv)
            grep -vE '^#|^$' "$output" | sed 's/\r$//' | cut -d',' -f1 | grep -v '^$'
            ;;
        *)
            cat "$output"
            ;;
    esac
    
    rm -f "$output"
    return 0
}

process_source() {
    local section="$1"
    local enable name type url format
    
    config_get enable "$section" enable "0"
    [ "$enable" = "1" ] || return 0
    
    config_get name "$section" name "$section"
    config_get type "$section" type "ip"
    config_get url "$section" url ""
    config_get format "$section" format "plain"
    
    [ -n "$url" ] || { log "WARNING: No URL for $name"; return 0; }
    
    local output="$TEMP_DIR/${type}_list.txt"
    download_source "$name" "$url" "$type" "$format" >> "$output" 2>/dev/null
    
    [ $? -eq 0 ] && log "SUCCESS: $name" || log "WARNING: Failed $name"
}

validate_ip() {
    echo "$1" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$'
}

validate_domain() {
    echo "$1" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
}

cleanup_list() {
    local input="$1" output="$2" type="$3"
    [ -f "$input" ] || return 1
    
    local valid=0 invalid=0
    
    while IFS= read -r line; do
        case "$line" in ""|\#*|";;;"*) continue ;; esac
        line=$(echo "$line" | tr -d ' \t\r')
        
        if [ "$type" = "ip" ]; then
            if validate_ip "$line"; then
                echo "$line"
                valid=$((valid + 1))
            else
                invalid=$((invalid + 1))
            fi
        else
            if validate_domain "$line"; then
                echo "$line"
                valid=$((valid + 1))
            else
                invalid=$((invalid + 1))
            fi
        fi
    done < "$input" | sort -u > "$output"
    
    log "Validated $type: $valid valid, $invalid invalid"
}

update_lists() {
    acquire_lock || return 1
    trap release_lock EXIT
    
    log "=========================================="
    log "Starting threat intelligence update"
    
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    touch "$TEMP_DIR/ip_list.txt" "$TEMP_DIR/domain_list.txt"
    
    config_load threat_intel
    config_foreach process_source source
    
    # Process IP list
    if [ -s "$TEMP_DIR/ip_list.txt" ]; then
        cleanup_list "$TEMP_DIR/ip_list.txt" "$IP_BLACKLIST.new" "ip"
        
        if [ -s "$IP_BLACKLIST.new" ]; then
            local ip_count=$(wc -l < "$IP_BLACKLIST.new")
            [ -f "$IP_BLACKLIST" ] && cp "$IP_BLACKLIST" "$IP_BLACKLIST.bak"
            mv "$IP_BLACKLIST.new" "$IP_BLACKLIST"
            log "Updated IP blacklist: $ip_count entries"
        fi
    fi
    
    # Process domain list
    if [ -s "$TEMP_DIR/domain_list.txt" ]; then
        cleanup_list "$TEMP_DIR/domain_list.txt" "$DOMAIN_BLACKLIST.new" "domain"
        
        if [ -s "$DOMAIN_BLACKLIST.new" ]; then
            local domain_count=$(wc -l < "$DOMAIN_BLACKLIST.new")
            [ -f "$DOMAIN_BLACKLIST" ] && cp "$DOMAIN_BLACKLIST" "$DOMAIN_BLACKLIST.bak"
            mv "$DOMAIN_BLACKLIST.new" "$DOMAIN_BLACKLIST"
            log "Updated domain blacklist: $domain_count entries"
        fi
    fi
    
    rm -rf "$TEMP_DIR"
    
    # Apply rules
    log "Applying threat rules..."
    [ -x /usr/bin/fwx-threat-apply ] && {
        /usr/bin/fwx-threat-apply hot 2>/dev/null || /usr/bin/fwx-threat-apply
    }
    
    date +%s > "$THREAT_DIR/.last_update"
    log "Update completed"
    log "=========================================="
    
    release_lock
    trap - EXIT
}

show_status() {
    echo "=== FWX Threat Intelligence Status ==="
    
    [ -f "$IP_BLACKLIST" ] && echo "IP Blacklist: $(wc -l < "$IP_BLACKLIST") entries" || echo "IP Blacklist: Not found"
    [ -f "$DOMAIN_BLACKLIST" ] && echo "Domain Blacklist: $(wc -l < "$DOMAIN_BLACKLIST") entries" || echo "Domain Blacklist: Not found"
    
    if [ -f "$THREAT_DIR/.last_update" ]; then
        local last=$(cat "$THREAT_DIR/.last_update")
        local now=$(date +%s)
        local age=$(( (now - last) / 3600 ))
        echo "Last Update: $age hours ago"
    else
        echo "Last Update: Never"
    fi
    
    echo ""
    if nft list table inet fwx_threat >/dev/null 2>&1; then
        echo "NFTables: Active"
    else
        echo "NFTables: Not loaded"
    fi
}

case "$1" in
    update) update_lists ;;
    status) show_status ;;
    help|--help|-h)
        echo "Usage: $0 {update|status|help}"
        ;;
    *)
        echo "Usage: $0 {update|status|help}"
        exit 1
        ;;
esac
