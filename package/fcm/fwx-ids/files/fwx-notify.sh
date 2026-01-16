#!/bin/sh
# FWX Alert Notification Script
# Copyright (c) 2026 FanchMWRT

. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_notify"
LOG_FILE="/tmp/log/fwx-notify.log"
RATE_FILE="/tmp/fwx-notify-rate"

# 确保日志目录存在
mkdir -p "$(dirname "$LOG_FILE")"

log_notify() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1 $2 $3" >> "$LOG_FILE"
}

check_rate_limit() {
    local max_rate
    config_get max_rate global rate_limit "10"
    [ "$max_rate" = "0" ] && return 0
    
    local hour=$(date '+%Y%m%d%H')
    local count=0
    
    if [ -f "$RATE_FILE" ]; then
        local saved_hour=$(head -1 "$RATE_FILE" 2>/dev/null)
        if [ "$saved_hour" = "$hour" ]; then
            count=$(tail -1 "$RATE_FILE" 2>/dev/null)
            count=${count:-0}
        fi
    fi
    
    [ "$count" -ge "$max_rate" ] && return 1
    
    count=$((count + 1))
    printf '%s\n%s\n' "$hour" "$count" > "$RATE_FILE"
    return 0
}

# 级别转数字
level_to_num() {
    case "$1" in
        info) echo 1 ;;
        warning) echo 2 ;;
        critical) echo 3 ;;
        emergency) echo 4 ;;
        *) echo 0 ;;
    esac
}

send_email() {
    local subject="$1"
    local body="$2"
    
    local smtp_server smtp_port smtp_security smtp_user smtp_pass from_addr subject_prefix
    
    config_get smtp_server email smtp_server ""
    config_get smtp_port email smtp_port "587"
    config_get smtp_security email smtp_security "starttls"
    config_get smtp_user email smtp_user ""
    config_get smtp_pass email smtp_pass ""
    config_get from_addr email from_addr ""
    config_get subject_prefix email subject_prefix "[FanchMWRT Alert]"
    
    [ -z "$smtp_server" ] || [ -z "$from_addr" ] && return 1
    
    local full_subject="$subject_prefix $subject"
    local security_opt=""
    
    case "$smtp_security" in
        starttls) security_opt="--starttls" ;;
        ssl) security_opt="--ssl" ;;
    esac
    
    # 发送给所有收件人
    local to_list=""
    config_list_foreach email to_addr _collect_email
    
    [ -z "$to_list" ] && return 1
    
    for to in $to_list; do
        _do_send_email "$to" "$full_subject" "$body" "$smtp_server" "$smtp_port" \
            "$security_opt" "$smtp_user" "$smtp_pass" "$from_addr" || return 1
    done
    
    return 0
}

_collect_email() {
    to_list="$to_list $1"
}

_do_send_email() {
    local to="$1" subject="$2" body="$3" server="$4" port="$5"
    local security="$6" user="$7" pass="$8" from="$9"
    
    local msg="Subject: $subject
From: $from
To: $to

$body"
    
    if command -v msmtp >/dev/null 2>&1; then
        printf '%s' "$msg" | msmtp --host="$server" --port="$port" $security \
            --auth=on --user="$user" --passwordeval="echo '$pass'" \
            --from="$from" "$to" 2>/dev/null
    elif command -v curl >/dev/null 2>&1; then
        printf '%s' "$msg" | curl -s --url "smtp://$server:$port" \
            --mail-from "$from" --mail-rcpt "$to" \
            --user "$user:$pass" $security \
            --upload-file - 2>/dev/null
    else
        return 1
    fi
}

send_webhook() {
    local payload="$1"
    
    local url method timeout verify_ssl
    config_get url webhook url ""
    config_get method webhook method "POST"
    config_get timeout webhook timeout "10"
    config_get verify_ssl webhook verify_ssl "1"
    
    [ -z "$url" ] && return 1
    
    local curl_opts="-s -X $method"
    curl_opts="$curl_opts -H 'Content-Type: application/json'"
    curl_opts="$curl_opts --connect-timeout $timeout"
    [ "$verify_ssl" = "0" ] && curl_opts="$curl_opts -k"
    
    # 添加自定义头
    local headers=""
    config_list_foreach webhook headers _add_header
    
    curl $curl_opts $headers -d "$payload" "$url" >/dev/null 2>&1
}

_add_header() {
    headers="$headers -H '$1'"
}

format_payload() {
    local level="$1" type="$2" src="$3" dst="$4" detail="$5" time="$6"
    
    local format
    config_get format webhook format "json"
    
    # 转义JSON特殊字符
    detail=$(printf '%s' "$detail" | sed 's/"/\\"/g; s/\\/\\\\/g')
    
    case "$format" in
        json)
            printf '{"level":"%s","type":"%s","src":"%s","dst":"%s","detail":"%s","time":"%s"}' \
                "$level" "$type" "$src" "$dst" "$detail" "$time"
            ;;
        slack)
            printf '{"text":"🚨 *%s* Alert: %s\\nSource: %s\\nDestination: %s\\nDetail: %s\\nTime: %s"}' \
                "$level" "$type" "$src" "$dst" "$detail" "$time"
            ;;
        discord)
            printf '{"content":"🚨 **%s** Alert: %s\\nSource: %s\\nDestination: %s\\nDetail: %s\\nTime: %s"}' \
                "$level" "$type" "$src" "$dst" "$detail" "$time"
            ;;
        telegram)
            local token chat_id
            config_get token webhook telegram_token ""
            config_get chat_id webhook telegram_chat_id ""
            # Telegram使用sendMessage API
            printf '{"chat_id":"%s","text":"🚨 %s Alert: %s\nSource: %s\nDestination: %s\nDetail: %s\nTime: %s","parse_mode":"HTML"}' \
                "$chat_id" "$level" "$type" "$src" "$dst" "$detail" "$time"
            ;;
        custom)
            local template
            config_get template webhook custom_template ""
            printf '%s' "$template" | sed \
                -e "s/{{level}}/$level/g" \
                -e "s/{{type}}/$type/g" \
                -e "s/{{src}}/$src/g" \
                -e "s/{{dst}}/$dst/g" \
                -e "s/{{detail}}/$detail/g" \
                -e "s/{{time}}/$time/g"
            ;;
    esac
}

get_webhook_url() {
    local format url
    config_get format webhook format "json"
    config_get url webhook url ""
    
    if [ "$format" = "telegram" ]; then
        local token
        config_get token webhook telegram_token ""
        [ -n "$token" ] && url="https://api.telegram.org/bot${token}/sendMessage"
    fi
    
    echo "$url"
}

send_alert() {
    local level="$1" type="$2" src="$3" dst="$4" detail="$5"
    
    [ -z "$level" ] || [ -z "$type" ] && return 1
    
    config_load "$CONFIG"
    
    # 检查是否启用
    local enabled
    config_get_bool enabled global enable 0
    [ "$enabled" = "0" ] && return 0
    
    # 检查级别阈值
    local min_level
    config_get min_level global min_level "warning"
    
    local level_num=$(level_to_num "$level")
    local min_num=$(level_to_num "$min_level")
    [ "$level_num" -lt "$min_num" ] && return 0
    
    # 检查告警类型是否启用
    local type_enabled
    config_get_bool type_enabled types "$type" 1
    [ "$type_enabled" = "0" ] && return 0
    
    # 检查速率限制
    check_rate_limit || {
        log_notify "RATE" "limited" "Rate limit exceeded"
        return 0
    }
    
    local time=$(date '+%Y-%m-%d %H:%M:%S')
    dst=${dst:-"-"}
    detail=${detail:-"-"}
    
    # 发送邮件
    local email_enabled
    config_get_bool email_enabled email enable 0
    if [ "$email_enabled" = "1" ]; then
        local subject="[$level] $type alert from $src"
        local body="Security Alert

Level: $level
Type: $type
Source: $src
Destination: $dst
Detail: $detail
Time: $time

--
FanchMWRT Security Center"
        
        if send_email "$subject" "$body"; then
            log_notify "email" "success" "$type"
        else
            log_notify "email" "failed" "$type"
        fi
    fi
    
    # 发送Webhook
    local webhook_enabled
    config_get_bool webhook_enabled webhook enable 0
    if [ "$webhook_enabled" = "1" ]; then
        local payload=$(format_payload "$level" "$type" "$src" "$dst" "$detail" "$time")
        
        # 处理Telegram特殊URL
        local format orig_url
        config_get format webhook format "json"
        if [ "$format" = "telegram" ]; then
            orig_url=$(uci get fwx_notify.webhook.url 2>/dev/null)
            local token
            config_get token webhook telegram_token ""
            [ -n "$token" ] && uci set fwx_notify.webhook.url="https://api.telegram.org/bot${token}/sendMessage"
        fi
        
        if send_webhook "$payload"; then
            log_notify "webhook" "success" "$type"
        else
            log_notify "webhook" "failed" "$type"
        fi
        
        # 恢复原URL
        [ -n "$orig_url" ] && uci set fwx_notify.webhook.url="$orig_url"
    fi
}

test_email() {
    config_load "$CONFIG"
    
    local subject="Test Alert"
    local body="This is a test alert from FanchMWRT Security Center.

Time: $(date)

If you received this email, your email notification is configured correctly.

--
FanchMWRT Security Center"
    
    if send_email "$subject" "$body"; then
        log_notify "email" "test_success" "Test"
        echo "Test email sent successfully"
        return 0
    else
        log_notify "email" "test_failed" "Test"
        echo "Test email failed"
        return 1
    fi
}

test_webhook() {
    config_load "$CONFIG"
    
    local time=$(date '+%Y-%m-%d %H:%M:%S')
    local payload=$(format_payload "info" "test" "127.0.0.1" "127.0.0.1" "Test notification" "$time")
    
    # 处理Telegram
    local format
    config_get format webhook format "json"
    if [ "$format" = "telegram" ]; then
        local token
        config_get token webhook telegram_token ""
        [ -n "$token" ] && {
            local orig_url=$(uci get fwx_notify.webhook.url 2>/dev/null)
            uci set fwx_notify.webhook.url="https://api.telegram.org/bot${token}/sendMessage"
        }
    fi
    
    if send_webhook "$payload"; then
        log_notify "webhook" "test_success" "Test"
        echo "Test webhook sent successfully"
        return 0
    else
        log_notify "webhook" "test_failed" "Test"
        echo "Test webhook failed"
        return 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 <command> [options]

Commands:
  send <level> <type> <src> [dst] [detail]
      Send an alert notification
      level: info, warning, critical, emergency
      type: threat_ip, portscan, synflood, bruteforce, malware, suricata, etc.
      
  test-email
      Send a test email
      
  test-webhook
      Send a test webhook

Examples:
  $0 send warning portscan 192.168.1.100 192.168.1.1 "Scanned 50 ports"
  $0 test-email
  $0 test-webhook
EOF
    exit 1
}

case "$1" in
    send)
        shift
        [ $# -lt 3 ] && usage
        send_alert "$@"
        ;;
    test-email)
        test_email
        ;;
    test-webhook)
        test_webhook
        ;;
    *)
        usage
        ;;
esac
