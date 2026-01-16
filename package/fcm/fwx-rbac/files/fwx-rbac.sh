#!/bin/sh
. /lib/functions.sh

CONFIG="fwx_rbac"

hash_password() {
    echo -n "$1" | md5sum | awk '{print $1}'
}

add_user() {
    local username="$1" password="$2" role="${3:-monitor}"
    [ -z "$username" ] || [ -z "$password" ] && { echo "Usage: $0 add-user <user> <pass> [role]"; return 1; }
    
    local hash=$(hash_password "$password")
    local cfg=$(uci add "$CONFIG" user)
    uci set "$CONFIG.$cfg.username=$username"
    uci set "$CONFIG.$cfg.password_hash=$hash"
    uci set "$CONFIG.$cfg.role=$role"
    uci set "$CONFIG.$cfg.enable=1"
    uci commit "$CONFIG"
    
    echo "User '$username' added with role '$role'"
}

del_user() {
    local username="$1"
    [ -z "$username" ] && { echo "Usage: $0 del-user <user>"; return 1; }
    
    config_load "$CONFIG"
    config_foreach _del_by_name user "$username"
    uci commit "$CONFIG"
    echo "User '$username' deleted"
}

_del_by_name() {
    local cfg="$1" target="$2" u
    config_get u "$cfg" username
    [ "$u" = "$target" ] && uci delete "$CONFIG.$cfg"
}

list_users() {
    echo "=== Users ==="
    config_load "$CONFIG"
    config_foreach _print_user user
}

_print_user() {
    local cfg="$1" username role enable
    config_get username "$cfg" username
    config_get role "$cfg" role
    config_get_bool enable "$cfg" enable 1
    printf "%-15s %-15s %s\n" "$username" "$role" "$([ "$enable" = "1" ] && echo "[ON]" || echo "[OFF]")"
}

case "$1" in
    add-user) add_user "$2" "$3" "$4" ;;
    del-user) del_user "$2" ;;
    list) list_users ;;
    *) echo "Usage: $0 {add-user|del-user|list}" ;;
esac
