#!/bin/sh
# FWX Suricata Manager
# Manages Suricata IDS/IPS integration with atomic nftables

. /lib/functions.sh
. /lib/fwx/nft_atomic.sh 2>/dev/null || true

# Constants
readonly SURICATA_BIN="/usr/bin/suricata"
readonly CONFIG_DIR="/etc/fwx/ids/suricata"
readonly SURICATA_CONF="$CONFIG_DIR/suricata.yaml"
readonly SURICATA_RULES="$CONFIG_DIR/rules"
readonly SURICATA_LOG="/tmp/log/suricata"
readonly SURICATA_PID="/var/run/suricata.pid"
readonly EVE_LOG="$SURICATA_LOG/eve.json"
readonly LOG_FILE="/tmp/log/fwx-suricata.log"
readonly UCI_CONFIG="fwx_suricata"
readonly NFT_TABLE="fwx_suricata"
readonly NFT_FILE="/tmp/fwx-suricata.nft"

log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" >> "$LOG_FILE"
    logger -t fwx-suricata -p "daemon.$level" "$*"
}

acquire_lock() {
    if type nft_lock >/dev/null 2>&1; then
        nft_lock "$NFT_TABLE" 30
    else
        local timeout=30 i=0
        while [ $i -lt $timeout ]; do
            if mkdir "/tmp/fwx-suricata.lock" 2>/dev/null; then
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
        rmdir "/tmp/fwx-suricata.lock" 2>/dev/null
    fi
}

check_installed() {
    [ -x "$SURICATA_BIN" ] || {
        log "error" "Suricata not installed"
        echo "Error: Suricata not installed. Install with: opkg install suricata"
        return 1
    }
}

is_running() {
    [ -f "$SURICATA_PID" ] && kill -0 "$(cat "$SURICATA_PID" 2>/dev/null)" 2>/dev/null
}

init_dirs() {
    mkdir -p "$CONFIG_DIR" "$SURICATA_RULES" "$SURICATA_LOG"
}

uci_get() {
    local key="$1" default="$2"
    local section="${3:-global}"
    config_load "$UCI_CONFIG"
    config_get value "$section" "$key" "$default"
    echo "$value"
}

uci_get_bool() {
    local key="$1" default="$2"
    local section="${3:-global}"
    config_load "$UCI_CONFIG"
    config_get_bool value "$section" "$key" "$default"
    echo "$value"
}

# 原子设置 NFQUEUE (IPS 模式)
setup_nfqueue_atomic() {
    local queue_num="${1:-0}"
    
    acquire_lock || return 1
    
    cat > "$NFT_FILE" <<EOF
# FWX Suricata NFQUEUE Atomic Ruleset
table inet $NFT_TABLE {
    chain forward {
        type filter hook forward priority 0; policy accept;
        queue num $queue_num bypass
    }
    
    chain input {
        type filter hook input priority 0; policy accept;
        queue num $queue_num bypass
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
        queue num $queue_num bypass
    }
}
EOF

    # 使用公共库或直接加载
    local result=0
    if type nft_atomic_load >/dev/null 2>&1; then
        nft_atomic_load "$NFT_FILE" "$NFT_TABLE" || result=1
    else
        nft delete table inet $NFT_TABLE 2>/dev/null
        nft -f "$NFT_FILE" || result=1
    fi
    
    if [ $result -eq 0 ]; then
        log "info" "NFQUEUE configured atomically (queue: $queue_num)"
    else
        log "error" "Failed to setup NFQUEUE"
    fi
    
    release_lock
    return $result
}

cleanup_nfqueue() {
    if type nft_safe_delete >/dev/null 2>&1; then
        nft_safe_delete "$NFT_TABLE"
    else
        nft delete table inet $NFT_TABLE 2>/dev/null
    fi
    log "info" "NFQUEUE cleaned up"
}

generate_config() {
    local interface=$(uci_get interface "br-lan")
    local home_net=$(uci_get home_net "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")
    local log_level=$(uci_get log_level "info")
    local stream_memcap=$(uci_get stream_memcap "32" performance)
    local flow_memcap=$(uci_get flow_memcap "32" performance)
    
    local eve_enable=$(uci_get_bool enable "1" eve)
    local log_alerts=$(uci_get_bool log_alerts "1" eve)
    local log_dns=$(uci_get_bool log_dns "1" eve)
    local log_http=$(uci_get_bool log_http "1" eve)
    local log_tls=$(uci_get_bool log_tls "1" eve)
    local log_flow=$(uci_get_bool log_flow "0" eve)
    local log_stats=$(uci_get_bool log_stats "1" eve)
    
    cat > "$SURICATA_CONF" <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[$home_net]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    SSH_SERVERS: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SSH_PORTS: "22"

default-log-dir: $SURICATA_LOG
logging:
  default-log-level: $log_level

stats:
  enabled: yes
  interval: 60

outputs:
  - eve-log:
      enabled: $([ "$eve_enable" = "1" ] && echo "yes" || echo "no")
      filetype: regular
      filename: eve.json
      community-id: true
      types:
$([ "$log_alerts" = "1" ] && echo "        - alert")
$([ "$log_dns" = "1" ] && echo "        - dns")
$([ "$log_http" = "1" ] && echo "        - http:")
$([ "$log_http" = "1" ] && echo "            extended: yes")
$([ "$log_tls" = "1" ] && echo "        - tls:")
$([ "$log_tls" = "1" ] && echo "            extended: yes")
$([ "$log_flow" = "1" ] && echo "        - flow")
$([ "$log_stats" = "1" ] && echo "        - stats:")
$([ "$log_stats" = "1" ] && echo "            totals: yes")

  - fast:
      enabled: yes
      filename: fast.log
      append: yes

af-packet:
  - interface: $interface
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

stream:
  memcap: ${stream_memcap}mb
  checksum-validation: yes
  inline: auto

flow:
  memcap: ${flow_memcap}mb
  hash-size: 65536
  prealloc: 10000

app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    dns:
      enabled: yes
    ssh:
      enabled: yes

default-rule-path: $SURICATA_RULES
rule-files:
  - "*.rules"
EOF

    log "info" "Generated config: interface=$interface"
}

download_rules() {
    log "info" "Downloading Suricata rules..."
    
    local et_open=$(uci_get_bool et_open "1" rules)
    local abuse_sslbl=$(uci_get_bool abuse_sslbl "1" rules)
    local custom_url=$(uci_get custom_rules_url "" rules)
    
    local temp_dir="/tmp/suricata_rules_$$"
    mkdir -p "$temp_dir"
    
    local success=0
    
    if [ "$et_open" = "1" ]; then
        local et_url="https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
        log "info" "Downloading ET Open rules..."
        
        if curl -sf -L --connect-timeout 30 --max-time 300 -o "$temp_dir/et.tar.gz" "$et_url"; then
            tar -xzf "$temp_dir/et.tar.gz" -C "$temp_dir" 2>/dev/null
            if [ -d "$temp_dir/rules" ]; then
                cp "$temp_dir/rules"/*.rules "$SURICATA_RULES/" 2>/dev/null
                success=1
                log "info" "ET Open rules downloaded"
            fi
        else
            log "warn" "Failed to download ET Open rules"
        fi
    fi
    
    if [ "$abuse_sslbl" = "1" ]; then
        local ssl_url="https://sslbl.abuse.ch/blacklist/sslblacklist.rules"
        log "info" "Downloading Abuse.ch SSL blacklist..."
        
        if curl -sf -L --connect-timeout 30 -o "$SURICATA_RULES/sslblacklist.rules" "$ssl_url"; then
            success=1
            log "info" "SSL blacklist downloaded"
        else
            log "warn" "Failed to download SSL blacklist"
        fi
    fi
    
    if [ -n "$custom_url" ]; then
        log "info" "Downloading custom rules from $custom_url"
        if curl -sf -L --connect-timeout 30 -o "$SURICATA_RULES/custom.rules" "$custom_url"; then
            success=1
            log "info" "Custom rules downloaded"
        else
            log "warn" "Failed to download custom rules"
        fi
    fi
    
    rm -rf "$temp_dir"
    
    local count=$(ls -1 "$SURICATA_RULES"/*.rules 2>/dev/null | wc -l)
    log "info" "Total rule files: $count"
    
    [ "$success" = "1" ]
}

start_suricata() {
    check_installed || return 1
    
    local enable=$(uci_get_bool enable "0")
    if [ "$enable" != "1" ]; then
        log "info" "Suricata disabled in config"
        echo "Suricata is disabled. Enable in config first."
        return 0
    fi
    
    if is_running; then
        log "info" "Suricata already running"
        echo "Suricata is already running"
        return 0
    fi
    
    init_dirs
    generate_config
    
    if [ -z "$(ls -A "$SURICATA_RULES" 2>/dev/null)" ]; then
        log "info" "No rules found, downloading..."
        download_rules || {
            log "error" "Failed to download rules"
            return 1
        }
    fi
    
    local interface=$(uci_get interface "br-lan")
    local mode=$(uci_get mode "ids")
    
    log "info" "Starting Suricata in $mode mode on $interface"
    
    if [ "$mode" = "ips" ]; then
        setup_nfqueue_atomic 0 || return 1
        $SURICATA_BIN -c "$SURICATA_CONF" -q 0 -D --pidfile "$SURICATA_PID"
    else
        $SURICATA_BIN -c "$SURICATA_CONF" --af-packet="$interface" -D --pidfile "$SURICATA_PID"
    fi
    
    if [ $? -eq 0 ]; then
        log "info" "Suricata started successfully"
        echo "Suricata started"
        return 0
    else
        log "error" "Failed to start Suricata"
        cleanup_nfqueue
        echo "Failed to start Suricata"
        return 1
    fi
}

stop_suricata() {
    if is_running; then
        local pid=$(cat "$SURICATA_PID")
        log "info" "Stopping Suricata (PID: $pid)"
        
        kill "$pid" 2>/dev/null
        
        local i=0
        while [ $i -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
            sleep 1
            i=$((i + 1))
        done
        
        kill -9 "$pid" 2>/dev/null
    fi
    
    rm -f "$SURICATA_PID"
    cleanup_nfqueue
    
    log "info" "Suricata stopped"
    echo "Suricata stopped"
}

reload_rules() {
    if is_running; then
        log "info" "Reloading Suricata rules"
        kill -USR2 "$(cat "$SURICATA_PID")"
        echo "Rules reloaded"
    else
        echo "Suricata not running"
        return 1
    fi
}

status_suricata() {
    echo "=== Suricata Status ==="
    
    if is_running; then
        echo "Status: Running (PID: $(cat "$SURICATA_PID"))"
        
        local mem=$(ps -o rss= -p "$(cat "$SURICATA_PID")" 2>/dev/null)
        [ -n "$mem" ] && echo "Memory: $((mem / 1024)) MB"
        
        if nft list table inet $NFT_TABLE >/dev/null 2>&1; then
            echo "Mode: IPS (NFQUEUE atomic)"
        else
            echo "Mode: IDS (AF_PACKET)"
        fi
    else
        echo "Status: Stopped"
    fi
    
    echo ""
    echo "Config: $SURICATA_CONF"
    echo "Rules: $SURICATA_RULES"
    echo "Logs: $SURICATA_LOG"
    
    local rule_count=$(ls -1 "$SURICATA_RULES"/*.rules 2>/dev/null | wc -l)
    echo "Rule files: $rule_count"
    
    if [ -f "$EVE_LOG" ]; then
        local alert_count=$(grep -c '"event_type":"alert"' "$EVE_LOG" 2>/dev/null || echo 0)
        echo "Alerts logged: $alert_count"
    fi
}

get_alerts() {
    local count="${1:-20}"
    
    [ -f "$EVE_LOG" ] || {
        echo "No EVE log found"
        return 1
    }
    
    grep '"event_type":"alert"' "$EVE_LOG" | tail -n "$count"
}

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  start         Start Suricata
  stop          Stop Suricata
  restart       Restart Suricata
  reload-rules  Reload rules without restart
  update-rules  Download and reload rules
  status        Show status
  alerts [n]    Show last n alerts (default: 20)

Examples:
  $0 start
  $0 update-rules
  $0 alerts 50
EOF
    exit 1
}

case "$1" in
    start)
        start_suricata
        ;;
    stop)
        stop_suricata
        ;;
    restart)
        stop_suricata
        sleep 2
        start_suricata
        ;;
    reload-rules)
        reload_rules
        ;;
    update-rules)
        download_rules && reload_rules
        ;;
    status)
        status_suricata
        ;;
    alerts)
        get_alerts "$2"
        ;;
    *)
        usage
        ;;
esac
