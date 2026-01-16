#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_urlfilter"
LISTS_DIR="/etc/fwx/urlfilter/lists"
DNSMASQ_CONF="/tmp/dnsmasq.d/fwx-urlfilter.conf"

update_lists() {
    mkdir -p "$LISTS_DIR"
    config_load "$CONFIG"
    
    download_category() {
        local cfg="$1"
        local enable url name
        config_get_bool enable "$cfg" enable 0
        [ "$enable" != "1" ] && return
        config_get url "$cfg" url
        config_get name "$cfg" name "$cfg"
        [ -n "$url" ] && {
            curl -sL "$url" -o "$LISTS_DIR/${cfg}.txt" 2>/dev/null
            logger -t fwx-urlfilter "Updated $name"
        }
    }
    config_foreach download_category category
}

generate_dnsmasq() {
    mkdir -p /tmp/dnsmasq.d
    > "$DNSMASQ_CONF"
    
    for list in "$LISTS_DIR"/*.txt; do
        [ -f "$list" ] || continue
        grep -v '^#' "$list" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | while read domain; do
            echo "address=/$domain/" >> "$DNSMASQ_CONF"
        done
    done
    
    /etc/init.d/dnsmasq restart
    logger -t fwx-urlfilter "DNS blocking applied"
}

start_filter() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    generate_dnsmasq
}

stop_filter() {
    rm -f "$DNSMASQ_CONF"
    /etc/init.d/dnsmasq restart
}

case "$1" in
    start) start_filter ;;
    stop) stop_filter ;;
    restart) stop_filter; start_filter ;;
    update) update_lists; generate_dnsmasq ;;
    *) echo "Usage: $0 {start|stop|restart|update}" ;;
esac
