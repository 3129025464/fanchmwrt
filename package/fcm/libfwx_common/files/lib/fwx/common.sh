#!/bin/sh
# FWX Common Shell Library
# Shared functions for all FWX modules

# 日志函数
fwx_log() {
    local tag="$1"
    local level="$2"
    local msg="$3"
    mkdir -p /tmp/log
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $msg" >> "/tmp/log/${tag}.log"
    logger -t "$tag" -p "daemon.$level" "$msg"
}

fwx_log_info() { fwx_log "$1" "info" "$2"; }
fwx_log_warn() { fwx_log "$1" "warn" "$2"; }
fwx_log_error() { fwx_log "$1" "error" "$2"; }

# 通用锁机制
FWX_LOCK_BASE="/tmp/fwx-locks"

fwx_lock() {
    local name="$1"
    local timeout="${2:-30}"
    local lock_dir="$FWX_LOCK_BASE/${name}.lock"
    local i=0
    
    mkdir -p "$FWX_LOCK_BASE"
    
    while [ $i -lt $timeout ]; do
        if mkdir "$lock_dir" 2>/dev/null; then
            echo $$ > "$lock_dir/pid"
            return 0
        fi
        
        # 检查持锁进程是否存活
        if [ -f "$lock_dir/pid" ]; then
            local pid=$(cat "$lock_dir/pid" 2>/dev/null)
            if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
                rm -rf "$lock_dir"
                continue
            fi
        fi
        
        sleep 1
        i=$((i + 1))
    done
    
    return 1
}

fwx_unlock() {
    local name="$1"
    rm -rf "$FWX_LOCK_BASE/${name}.lock"
}

# IP 验证
fwx_validate_ipv4() {
    echo "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
}

fwx_validate_ipv6() {
    echo "$1" | grep -qE '^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$'
}

# 域名验证
fwx_validate_domain() {
    echo "$1" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
}

# 端口验证
fwx_validate_port() {
    local port="$1"
    [ -n "$port" ] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] 2>/dev/null
}

# MAC 地址验证
fwx_validate_mac() {
    echo "$1" | grep -qE '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$'
}

# 获取 WAN 接口
fwx_get_wan_device() {
    . /lib/functions/network.sh 2>/dev/null
    local dev
    network_get_device dev wan 2>/dev/null
    [ -z "$dev" ] && dev=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    echo "$dev"
}

# 获取 LAN 接口
fwx_get_lan_device() {
    . /lib/functions/network.sh 2>/dev/null
    local dev
    network_get_device dev lan 2>/dev/null
    [ -z "$dev" ] && dev="br-lan"
    echo "$dev"
}

# UCI 辅助函数
fwx_uci_get() {
    local config="$1"
    local section="$2"
    local option="$3"
    local default="$4"
    
    local value=$(uci -q get "${config}.${section}.${option}")
    echo "${value:-$default}"
}

fwx_uci_get_bool() {
    local config="$1"
    local section="$2"
    local option="$3"
    local default="${4:-0}"
    
    local value=$(uci -q get "${config}.${section}.${option}")
    case "$value" in
        1|yes|true|on) echo "1" ;;
        0|no|false|off) echo "0" ;;
        *) echo "$default" ;;
    esac
}

fwx_uci_set() {
    local config="$1"
    local section="$2"
    local option="$3"
    local value="$4"
    
    uci -q set "${config}.${section}.${option}=${value}"
}

fwx_uci_commit() {
    local config="$1"
    uci commit "$config" 2>/dev/null
}

# 发送告警到 fwxd
# 用法: fwx_alert <module> <level> <type> <src> <detail> [dst]
# module: fwx-ids, fwx-threat, fwx-av, fwx-ddos, etc.
# level: info, warning, critical, emergency
# type: threat_ip, threat_domain, portscan, synflood, bruteforce, malware, ids, system
fwx_alert() {
    local module="$1"
    local level="$2"
    local type="$3"
    local src="$4"
    local detail="$5"
    local dst="${6:-}"
    
    local json="{\"module\":\"$module\",\"level\":\"$level\",\"type\":\"$type\",\"src\":\"$src\",\"detail\":\"$detail\""
    [ -n "$dst" ] && json="$json,\"dst\":\"$dst\""
    json="$json}"
    
    ubus call fwx alert "$json" 2>/dev/null
}

# 简化版告警（向后兼容）
fwx_alert_simple() {
    local type="$1"
    local src="$2"
    local detail="$3"
    fwx_alert "unknown" "warning" "$type" "$src" "$detail"
}

# 确保目录存在
fwx_ensure_dir() {
    for dir in "$@"; do
        [ -d "$dir" ] || mkdir -p "$dir"
    done
}

# 检查命令是否存在
fwx_cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 安全执行命令（带超时）
fwx_timeout_exec() {
    local timeout="$1"
    shift
    
    if fwx_cmd_exists timeout; then
        timeout "$timeout" "$@"
    else
        "$@"
    fi
}

# 获取系统内存（MB）
fwx_get_mem_mb() {
    awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo "0"
}

# 获取 CPU 核心数
fwx_get_cpu_cores() {
    grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "1"
}
