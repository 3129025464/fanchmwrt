#!/bin/sh
# FWX OUI Database Update Script
# Downloads and processes IEEE OUI database

OUI_DIR="/etc/fwx"
OUI_FILE="$OUI_DIR/oui.txt"
OUI_URL="https://standards-oui.ieee.org/oui/oui.txt"
TEMP_FILE="/tmp/oui_raw.txt"

log() {
    logger -t fwx-oui "$1"
    echo "$1"
}

download_oui() {
    log "Downloading OUI database..."
    
    if ! curl -sf -L --connect-timeout 30 --max-time 300 \
         -o "$TEMP_FILE" "$OUI_URL" 2>/dev/null; then
        log "ERROR: Failed to download OUI database"
        return 1
    fi
    
    if [ ! -s "$TEMP_FILE" ]; then
        log "ERROR: Downloaded file is empty"
        return 1
    fi
    
    log "Download complete, processing..."
    return 0
}

process_oui() {
    mkdir -p "$OUI_DIR"
    
    # 解析 IEEE OUI 格式
    # 格式: XX-XX-XX   (hex)    Vendor Name
    awk '
    /^[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}.*\(hex\)/ {
        oui = $1
        gsub(/-/, ":", oui)
        
        # 提取厂商名称 (跳过 (hex) 标记)
        vendor = ""
        for (i = 3; i <= NF; i++) {
            if (vendor != "") vendor = vendor " "
            vendor = vendor $i
        }
        
        # 清理厂商名称
        gsub(/^[ \t]+|[ \t]+$/, "", vendor)
        gsub(/\t/, " ", vendor)
        
        if (length(vendor) > 0 && length(vendor) < 64) {
            print oui "\t" vendor
        }
    }
    ' "$TEMP_FILE" > "$OUI_FILE.new"
    
    local count=$(wc -l < "$OUI_FILE.new")
    
    if [ "$count" -lt 1000 ]; then
        log "ERROR: Parsed OUI count too low ($count), keeping old database"
        rm -f "$OUI_FILE.new"
        return 1
    fi
    
    mv "$OUI_FILE.new" "$OUI_FILE"
    rm -f "$TEMP_FILE"
    
    log "OUI database updated: $count entries"
    return 0
}

# 添加常见厂商的快速查找表
add_common_vendors() {
    cat >> "$OUI_FILE" << 'EOF'
# Common vendors quick lookup
00:00:00	XEROX CORPORATION
00:50:56	VMware, Inc.
08:00:27	Oracle VirtualBox
52:54:00	QEMU Virtual NIC
B8:27:EB	Raspberry Pi Foundation
DC:A6:32	Raspberry Pi Trading Ltd
E4:5F:01	Raspberry Pi Trading Ltd
EOF
}

case "$1" in
    update)
        download_oui && process_oui
        ;;
    status)
        if [ -f "$OUI_FILE" ]; then
            echo "OUI Database: $OUI_FILE"
            echo "Entries: $(wc -l < "$OUI_FILE")"
            echo "Last modified: $(stat -c %y "$OUI_FILE" 2>/dev/null || stat -f %Sm "$OUI_FILE")"
        else
            echo "OUI Database: Not found"
        fi
        ;;
    *)
        echo "Usage: $0 {update|status}"
        exit 1
        ;;
esac
