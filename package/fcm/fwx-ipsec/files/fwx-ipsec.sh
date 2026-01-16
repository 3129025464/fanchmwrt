#!/bin/sh
. /lib/functions.sh
. /lib/fwx/common.sh 2>/dev/null || true

CONFIG="fwx_ipsec"
SWANCTL_CONF="/etc/swanctl/conf.d/fwx-ipsec.conf"

generate_config() {
    mkdir -p /etc/swanctl/conf.d
    
    cat > "$SWANCTL_CONF" << 'EOF'
connections {
EOF

    config_load "$CONFIG"
    config_foreach gen_tunnel tunnel
    
    echo "}" >> "$SWANCTL_CONF"
    echo "secrets {" >> "$SWANCTL_CONF"
    config_foreach gen_secret tunnel
    echo "}" >> "$SWANCTL_CONF"
}

gen_tunnel() {
    local cfg="$1"
    local enable name remote local_subnet remote_subnet psk ike esp
    
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    
    config_get name "$cfg" name "$cfg"
    config_get remote "$cfg" remote_gateway
    config_get local_subnet "$cfg" local_subnet
    config_get remote_subnet "$cfg" remote_subnet
    config_get ike "$cfg" ike_proposal "aes256-sha256-modp2048"
    config_get esp "$cfg" esp_proposal "aes256-sha256"
    
    [ -z "$remote" ] && return
    
    cat >> "$SWANCTL_CONF" << EOF
    $cfg {
        version = 2
        proposals = $ike
        local { auth = psk }
        remote { auth = psk; id = $remote }
        children {
            ${cfg}_child {
                local_ts = $local_subnet
                remote_ts = $remote_subnet
                esp_proposals = $esp
                start_action = start
            }
        }
    }
EOF
}

gen_secret() {
    local cfg="$1"
    local enable psk remote
    config_get_bool enable "$cfg" enable 0
    [ "$enable" != "1" ] && return
    config_get psk "$cfg" psk
    config_get remote "$cfg" remote_gateway
    [ -z "$psk" ] && return
    
    cat >> "$SWANCTL_CONF" << EOF
    ike-$cfg { id = $remote; secret = "$psk" }
EOF
}

start_ipsec() {
    local enable
    config_load "$CONFIG"
    config_get_bool enable global enable 0
    [ "$enable" != "1" ] && return 0
    
    generate_config
    /etc/init.d/strongswan start 2>/dev/null
    sleep 2
    swanctl --load-all 2>/dev/null
    logger -t fwx-ipsec "IPSec started"
}

stop_ipsec() {
    /etc/init.d/strongswan stop 2>/dev/null
    logger -t fwx-ipsec "IPSec stopped"
}

case "$1" in
    start) start_ipsec ;;
    stop) stop_ipsec ;;
    restart) stop_ipsec; sleep 1; start_ipsec ;;
    reload) generate_config; swanctl --load-all ;;
    status) swanctl --list-sas 2>/dev/null ;;
    *) echo "Usage: $0 {start|stop|restart|reload|status}" ;;
esac
