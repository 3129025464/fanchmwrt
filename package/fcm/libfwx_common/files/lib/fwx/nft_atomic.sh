#!/bin/sh
# FWX NFTables Atomic Operations Library
# Provides atomic ruleset loading with connection preservation

# 全局锁目录
NFT_LOCK_BASE="/tmp/fwx-nft-locks"

# 初始化锁目录
nft_init() {
    mkdir -p "$NFT_LOCK_BASE"
}

# 获取表级别的锁
# Usage: nft_lock <table_name> [timeout]
nft_lock() {
    local table="$1"
    local timeout="${2:-30}"
    local lock_dir="$NFT_LOCK_BASE/$table.lock"
    local i=0
    
    while [ $i -lt $timeout ]; do
        if mkdir "$lock_dir" 2>/dev/null; then
            echo $$ > "$lock_dir/pid"
            return 0
        fi
        
        # 检查持锁进程是否还存在
        if [ -f "$lock_dir/pid" ]; then
            local pid=$(cat "$lock_dir/pid" 2>/dev/null)
            if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
                # 持锁进程已死，清理锁
                rm -rf "$lock_dir"
                continue
            fi
        fi
        
        sleep 1
        i=$((i + 1))
    done
    
    return 1
}

# 释放锁
# Usage: nft_unlock <table_name>
nft_unlock() {
    local table="$1"
    local lock_dir="$NFT_LOCK_BASE/$table.lock"
    rm -rf "$lock_dir"
}

# 原子加载规则集文件
# Usage: nft_atomic_load <nft_file> [backup_table]
# 如果提供 backup_table，会在加载失败时尝试恢复
nft_atomic_load() {
    local nft_file="$1"
    local backup_table="$2"
    local backup_file=""
    
    [ -f "$nft_file" ] || {
        echo "Error: ruleset file not found: $nft_file" >&2
        return 1
    }
    
    # 备份现有表（如果指定）
    if [ -n "$backup_table" ]; then
        backup_file="/tmp/nft-backup-${backup_table}-$$.nft"
        nft list table inet "$backup_table" > "$backup_file" 2>/dev/null
    fi
    
    # 原子加载
    if nft -f "$nft_file" 2>/dev/null; then
        [ -n "$backup_file" ] && rm -f "$backup_file"
        return 0
    else
        # 加载失败，尝试恢复
        if [ -s "$backup_file" ]; then
            nft -f "$backup_file" 2>/dev/null
            rm -f "$backup_file"
        fi
        return 1
    fi
}

# 原子替换表（不打断现有连接）
# Usage: nft_atomic_replace <table_name> <new_ruleset_file>
# 策略：先加载新表（临时名），再原子切换
nft_atomic_replace() {
    local table="$1"
    local new_file="$2"
    local temp_table="${table}_new"
    local switch_file="/tmp/nft-switch-$$.nft"
    
    [ -f "$new_file" ] || return 1
    
    # 1. 将新规则集中的表名改为临时名
    sed "s/table inet $table/table inet $temp_table/g" "$new_file" > "/tmp/nft-temp-$$.nft"
    
    # 2. 加载临时表
    if ! nft -f "/tmp/nft-temp-$$.nft" 2>/dev/null; then
        rm -f "/tmp/nft-temp-$$.nft"
        return 1
    fi
    
    # 3. 原子切换：生成切换脚本
    cat > "$switch_file" <<EOF
delete table inet $table
EOF
    
    # 追加重命名后的规则
    sed "s/table inet $temp_table/table inet $table/g" "/tmp/nft-temp-$$.nft" >> "$switch_file"
    
    # 4. 删除临时表
    nft delete table inet "$temp_table" 2>/dev/null
    
    # 5. 执行切换
    if nft -f "$switch_file" 2>/dev/null; then
        rm -f "/tmp/nft-temp-$$.nft" "$switch_file"
        return 0
    else
        rm -f "/tmp/nft-temp-$$.nft" "$switch_file"
        return 1
    fi
}

# 导出表中的 set 元素
# Usage: nft_export_sets <table_name> <output_file>
nft_export_sets() {
    local table="$1"
    local output="$2"
    
    : > "$output"
    
    nft list table inet "$table" 2>/dev/null | \
    awk -v table="$table" '
        /^[[:space:]]*set [a-zA-Z_][a-zA-Z0-9_]* \{/ {
            in_set = 1
            set_name = $2
            next
        }
        in_set && /elements = \{/ {
            in_elements = 1
            gsub(/.*elements = \{ */, "")
            gsub(/ *\}.*/, "")
            if (length($0) > 0) {
                n = split($0, elems, ",")
                for (i = 1; i <= n; i++) {
                    gsub(/^ +| +$/, "", elems[i])
                    if (length(elems[i]) > 0) {
                        print "add element inet " table " " set_name " { " elems[i] " }"
                    }
                }
            }
            next
        }
        in_set && /^\t\}/ {
            in_set = 0
            in_elements = 0
        }
    ' >> "$output"
}

# 恢复 set 元素到表
# Usage: nft_restore_sets <table_name> <sets_file>
nft_restore_sets() {
    local table="$1"
    local sets_file="$2"
    
    [ -s "$sets_file" ] || return 0
    
    # 替换表名（如果需要）
    nft -f "$sets_file" 2>/dev/null
}

# 安全删除表
# Usage: nft_safe_delete <table_name>
nft_safe_delete() {
    local table="$1"
    nft delete table inet "$table" 2>/dev/null
    return 0
}

# 检查表是否存在
# Usage: nft_table_exists <table_name>
nft_table_exists() {
    local table="$1"
    nft list table inet "$table" >/dev/null 2>&1
}

# 获取表统计信息
# Usage: nft_get_stats <table_name>
nft_get_stats() {
    local table="$1"
    
    if ! nft_table_exists "$table"; then
        echo "Table $table not found"
        return 1
    fi
    
    echo "=== Table: $table ==="
    nft list table inet "$table" 2>/dev/null | grep -E "counter|packets|bytes"
}

# 批量添加元素到 set（原子操作）
# Usage: nft_batch_add_elements <table> <set> <elements_file>
# elements_file 每行一个元素
nft_batch_add_elements() {
    local table="$1"
    local set="$2"
    local elements_file="$3"
    local batch_file="/tmp/nft-batch-$$.nft"
    local batch_size=500
    local count=0
    local elements=""
    
    [ -f "$elements_file" ] || return 1
    
    : > "$batch_file"
    
    while IFS= read -r elem || [ -n "$elem" ]; do
        [ -z "$elem" ] && continue
        
        if [ -z "$elements" ]; then
            elements="$elem"
        else
            elements="$elements, $elem"
        fi
        
        count=$((count + 1))
        
        if [ $count -ge $batch_size ]; then
            echo "add element inet $table $set { $elements }" >> "$batch_file"
            elements=""
            count=0
        fi
    done < "$elements_file"
    
    # 剩余元素
    if [ -n "$elements" ]; then
        echo "add element inet $table $set { $elements }" >> "$batch_file"
    fi
    
    # 原子执行
    if [ -s "$batch_file" ]; then
        nft -f "$batch_file" 2>/dev/null
        local ret=$?
        rm -f "$batch_file"
        return $ret
    fi
    
    rm -f "$batch_file"
    return 0
}

nft_init
