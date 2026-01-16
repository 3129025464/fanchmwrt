#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_vpn"
VPN_DIR="/etc/fwx/vpn"

gen_keys() {
    local priv=$(wg genkey)
    local pub=$(echo "$priv" | wg pubkey)
    echo "$priv:$pub"
}

init_server() {
    local keys=$(gen_keys)
    local priv="${keys%:*}"
    local pub="${keys#*:}"
    
    uci set $CONFIG.server.private_key="$priv"
    uci set $CONFIG.server.public_key="$pub"
    uci commit $CONFIG
    
    echo "Server initialized"
    echo "Public Key: $pub"
}

start_vpn() {
    local enable port address private_key
    config_load "$CONFIG"
    config_get_bool enable server enable 0
    [ "$enable" != "1" ] && return 0
    
    config_get port server port "51820"
    config_get address server address "10.10.10.1/24"
    config_get private_key server private_key
    
    [ -z "$private_key" ] && { echo "Run '$0 init' first"; return 1; }
    
    ip link add wg0 type wireguard 2>/dev/null
    ip addr add "$address" dev wg0 2>/dev/null
    wg set wg0 private-key <(echo "$private_key") listen-port "$port"
    ip link set wg0 up
    
    # Add clients
    config_foreach add_peer client
    
    # Firewall
    nft add table inet fwx_vpn 2>/dev/null
    nft add chain inet fwx_vpn input '{ type filter hook input priority -100; }' 2>/dev/null
    nft add rule inet fwx_vpn input udp dport "$port" accept 2>/dev/null
    
    logger -t fwx-vpn "VPN started on port $port"
}

add_peer() {
    local cfg="$1"
    local enable pubkey allowed_ips
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    config_get pubkey "$cfg" public_key
    config_get allowed_ips "$cfg" allowed_ips
    [ -n "$pubkey" ] && wg set wg0 peer "$pubkey" allowed-ips "$allowed_ips"
}

stop_vpn() {
    ip link del wg0 2>/dev/null
    nft delete table inet fwx_vpn 2>/dev/null
    logger -t fwx-vpn "VPN stopped"
}

add_client() {
    local name="$1"
    [ -z "$name" ] && { echo "Usage: $0 add-client <name>"; return 1; }
    
    local server_pub server_port server_addr dns
    config_load "$CONFIG"
    config_get server_pub server public_key
    config_get server_port server port "51820"
    config_get server_addr server address "10.10.10.1/24"
    config_get dns server dns "8.8.8.8"
    
    local keys=$(gen_keys)
    local priv="${keys%:*}"
    local pub="${keys#*:}"
    
    # Get next IP
    local last_ip=$(uci show $CONFIG | grep -oE '10\.10\.10\.[0-9]+' | sort -t. -k4 -n | tail -1)
    local next_num=$((${last_ip##*.} + 1))
    [ "$next_num" -lt 2 ] && next_num=2
    local client_ip="10.10.10.$next_num/32"
    
    # Save client
    local cfg=$(uci add $CONFIG client)
    uci set $CONFIG.$cfg.name="$name"
    uci set $CONFIG.$cfg.enable="1"
    uci set $CONFIG.$cfg.public_key="$pub"
    uci set $CONFIG.$cfg.allowed_ips="$client_ip"
    uci commit $CONFIG
    
    # Generate config
    mkdir -p "$VPN_DIR/clients/$name"
    local endpoint=$(ip route get 8.8.8.8 | grep -oE 'src [0-9.]+' | cut -d' ' -f2)
    
    cat > "$VPN_DIR/clients/$name/wg0.conf" << EOF
[Interface]
PrivateKey = $priv
Address = ${client_ip%/*}/24
DNS = $dns

[Peer]
PublicKey = $server_pub
Endpoint = $endpoint:$server_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    qrencode -t PNG -o "$VPN_DIR/clients/$name/qrcode.png" < "$VPN_DIR/clients/$name/wg0.conf" 2>/dev/null
    
    echo "Client '$name' created"
    echo "Config: $VPN_DIR/clients/$name/wg0.conf"
}

case "$1" in
    start) start_vpn ;;
    stop) stop_vpn ;;
    restart) stop_vpn; start_vpn ;;
    init) init_server ;;
    add-client) add_client "$2" ;;
    status) wg show 2>/dev/null ;;
    *) echo "Usage: $0 {start|stop|restart|init|add-client|status}" ;;
esac
