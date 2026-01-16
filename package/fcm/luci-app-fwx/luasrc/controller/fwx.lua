-- FanchMWRT Security Center Controller
-- Copyright (c) 2026 FanchMWRT

module("luci.controller.fwx", package.seeall)

-- 常量定义
local PATHS = {
    LOG_SECURITY = "/tmp/log/fwx-security.log",
    LOG_NOTIFY = "/tmp/log/fwx-notify.log",
    LOG_SURICATA = "/tmp/log/suricata/eve.json",
    THREAT_IPS = "/etc/fwx/threat/ip_blacklist.txt",
    THREAT_DOMAINS = "/etc/fwx/threat/domain_blacklist.txt",
    QUARANTINE = "/etc/fwx/av/quarantine",
    TRAFFIC_CACHE = "/tmp/fwx/traffic_stats.json"
}

local SERVICES = {
    [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS",
    [80] = "HTTP", [110] = "POP3", [143] = "IMAP", [443] = "HTTPS",
    [993] = "IMAPS", [995] = "POP3S", [3306] = "MySQL", [5432] = "PostgreSQL",
    [6379] = "Redis", [8080] = "HTTP-Alt", [8443] = "HTTPS-Alt"
}

-- 工具函数
local function json_response(data)
    local json = require "luci.jsonc"
    luci.http.prepare_content("application/json")
    luci.http.write(json.stringify(data))
end

local function file_exists(path)
    local fs = require "nixio.fs"
    return fs.access(path)
end

local function read_file(path)
    local fs = require "nixio.fs"
    return fs.readfile(path)
end

local function exec_cmd(cmd)
    local sys = require "luci.sys"
    return sys.exec(cmd)
end

local function call_cmd(cmd)
    local sys = require "luci.sys"
    return sys.call(cmd)
end

local function count_lines(file)
    if not file_exists(file) then return 0 end
    local count = exec_cmd("wc -l < " .. file .. " 2>/dev/null")
    return tonumber(count) or 0
end

local function read_log_lines(file, max_lines, reverse)
    local lines = {}
    if not file_exists(file) then return lines end
    
    local count = 0
    for line in io.lines(file) do
        if count < max_lines then
            if reverse then
                table.insert(lines, 1, line)
            else
                table.insert(lines, line)
            end
            count = count + 1
        elseif not reverse then
            break
        end
    end
    return lines
end

local function validate_ip(ip)
    return ip and ip:match("^%d+%.%d+%.%d+%.%d+$")
end

local function validate_path(path)
    return path and path:match("^/[%w%-%_/%.]+$")
end

-- 路由注册
function index()
    local base = {"admin", "fwx_security"}
    
    entry(base, firstchild(), _("Security Center"), 55).dependent = false
    
    -- 页面
    entry({base[1], base[2], "dashboard"}, template("fwx/dashboard"), _("Dashboard"), 10)
    entry({base[1], base[2], "threat"}, cbi("fwx/threat"), _("Threat Intel"), 20)
    entry({base[1], base[2], "ids"}, cbi("fwx/ids"), _("IDS/IPS"), 30)
    entry({base[1], base[2], "suricata"}, cbi("fwx/suricata"), _("Suricata IDS"), 35)
    entry({base[1], base[2], "av"}, cbi("fwx/av"), _("Antivirus"), 40)
    entry({base[1], base[2], "alerts"}, template("fwx/alerts"), _("Alerts"), 50)
    entry({base[1], base[2], "traffic"}, cbi("fwx/traffic"), _("Traffic Analysis"), 60)
    entry({base[1], base[2], "notify"}, cbi("fwx/notify"), _("Notifications"), 70)
    entry({base[1], base[2], "settings"}, cbi("fwx/settings"), _("Settings"), 90)
    
    -- API
    local api = {base[1], base[2], "api"}
    entry({api[1], api[2], api[3], "status"}, call("api_status")).leaf = true
    entry({api[1], api[2], api[3], "stats"}, call("api_stats")).leaf = true
    entry({api[1], api[2], api[3], "alerts"}, call("api_alerts")).leaf = true
    entry({api[1], api[2], api[3], "alerts_clear"}, post("api_alerts_clear")).leaf = true
    entry({api[1], api[2], api[3], "threat_update"}, post("api_threat_update")).leaf = true
    entry({api[1], api[2], api[3], "ids_unblock"}, post("api_ids_unblock")).leaf = true
    entry({api[1], api[2], api[3], "av_status"}, call("api_av_status")).leaf = true
    entry({api[1], api[2], api[3], "av_scan"}, post("api_av_scan")).leaf = true
    entry({api[1], api[2], api[3], "av_update"}, post("api_av_update")).leaf = true
    entry({api[1], api[2], api[3], "suricata_status"}, call("api_suricata_status")).leaf = true
    entry({api[1], api[2], api[3], "suricata_control"}, post("api_suricata_control")).leaf = true
    entry({api[1], api[2], api[3], "suricata_alerts"}, call("api_suricata_alerts")).leaf = true
    entry({api[1], api[2], api[3], "traffic_stats"}, call("api_traffic_stats")).leaf = true
    entry({api[1], api[2], api[3], "notify_test"}, post("api_notify_test")).leaf = true
    entry({api[1], api[2], api[3], "notify_history"}, call("api_notify_history")).leaf = true
    entry({api[1], api[2], api[3], "hardware_profile"}, call("api_hardware_profile")).leaf = true
    entry({api[1], api[2], api[3], "apply_profile"}, post("api_apply_profile")).leaf = true
end

-- API: 系统状态
function api_status()
    local uci = require "luci.model.uci".cursor()
    
    json_response({
        fwxd = call_cmd("pidof fwxd >/dev/null") == 0,
        threat = call_cmd("nft list table inet fwx_threat >/dev/null 2>&1") == 0,
        ids = call_cmd("nft list table inet fwx_ids >/dev/null 2>&1") == 0,
        suricata = call_cmd("pidof suricata >/dev/null") == 0,
        appfilter = uci:get("fwx", "appfilter", "enable") == "1",
        macfilter = uci:get("fwx", "macfilter", "enable") == "1"
    })
end

-- API: 统计数据
function api_stats()
    local today = os.date("%Y-%m-%d")
    local alerts_cmd = "grep -c '" .. today .. "' " .. PATHS.LOG_SECURITY .. " 2>/dev/null"
    local blocked_cmd = "nft list set inet fwx_ids blocked_ips 2>/dev/null | grep -c 'elements'"
    
    json_response({
        threat_ips = count_lines(PATHS.THREAT_IPS),
        threat_domains = count_lines(PATHS.THREAT_DOMAINS),
        ids_blocked = tonumber(exec_cmd(blocked_cmd)) or 0,
        alerts_today = tonumber(exec_cmd(alerts_cmd)) or 0
    })
end

-- API: 告警列表
function api_alerts()
    json_response({alerts = read_log_lines(PATHS.LOG_SECURITY, 100, true)})
end

-- API: 清空告警
function api_alerts_clear()
    local fs = require "nixio.fs"
    if file_exists(PATHS.LOG_SECURITY) then
        fs.writefile(PATHS.LOG_SECURITY, "")
    end
    json_response({success = true, message = "Alerts cleared"})
end

-- API: 更新威胁情报
function api_threat_update()
    call_cmd("/usr/bin/fwx-threat-update update &")
    json_response({success = true, message = "Update started"})
end

-- API: IDS解封IP
function api_ids_unblock()
    local ip = luci.http.formvalue("ip")
    
    if not validate_ip(ip) then
        json_response({success = false, message = "Invalid IP"})
        return
    end
    
    call_cmd("/usr/bin/fwx-ids unblock " .. ip)
    json_response({success = true, message = "IP unblocked"})
end

-- API: AV状态
function api_av_status()
    local count_cmd = "ls -1 " .. PATHS.QUARANTINE .. "/*.infected 2>/dev/null | wc -l"
    
    json_response({
        installed = file_exists("/usr/bin/clamscan"),
        realtime_running = file_exists("/tmp/fwx-av-realtime.pid"),
        quarantine_count = tonumber(exec_cmd(count_cmd)) or 0
    })
end

-- API: AV扫描
function api_av_scan()
    local path = luci.http.formvalue("path")
    
    if not validate_path(path) then
        json_response({success = false, message = "Invalid path"})
        return
    end
    
    call_cmd("/usr/bin/fwx-av scan '" .. path .. "' &")
    json_response({success = true, message = "Scan started"})
end

-- API: AV更新
function api_av_update()
    call_cmd("/usr/bin/fwx-av update &")
    json_response({success = true, message = "Update started"})
end

-- API: Suricata状态
function api_suricata_status()
    local rules_cmd = "ls -1 /etc/fwx/ids/suricata/rules/*.rules 2>/dev/null | wc -l"
    local mem_cmd = "ps -o rss= -p $(pidof suricata) 2>/dev/null"
    local alerts_cmd = "grep -c '\"event_type\":\"alert\"' " .. PATHS.LOG_SURICATA .. " 2>/dev/null"
    
    local mem = tonumber(exec_cmd(mem_cmd)) or 0
    local mem_str = mem > 0 and string.format("%.1f MB", mem / 1024) or "-"
    
    json_response({
        installed = file_exists("/usr/bin/suricata"),
        running = call_cmd("pidof suricata >/dev/null") == 0,
        rules_count = tonumber(exec_cmd(rules_cmd)) or 0,
        alerts_today = tonumber(exec_cmd(alerts_cmd)) or 0,
        memory = mem_str
    })
end

-- API: Suricata控制
function api_suricata_control()
    local action = luci.http.formvalue("action")
    local actions = {
        start = {cmd = "/usr/bin/fwx-suricata start", msg = "Suricata started"},
        stop = {cmd = "/usr/bin/fwx-suricata stop", msg = "Suricata stopped"},
        restart = {cmd = "/usr/bin/fwx-suricata restart", msg = "Suricata restarted"},
        ["update-rules"] = {cmd = "/usr/bin/fwx-suricata update-rules &", msg = "Rules update started"},
        ["reload-rules"] = {cmd = "/usr/bin/fwx-suricata reload-rules", msg = "Rules reloaded"}
    }
    
    local act = actions[action]
    if not act then
        json_response({success = false, message = "Invalid action"})
        return
    end
    
    call_cmd(act.cmd)
    json_response({success = true, message = act.msg})
end

-- API: Suricata告警
function api_suricata_alerts()
    local json = require "luci.jsonc"
    local alerts = {}
    
    if not file_exists(PATHS.LOG_SURICATA) then
        json_response({alerts = alerts})
        return
    end
    
    -- 使用tail获取最后100行，避免读取大文件
    local lines = exec_cmd("tail -100 " .. PATHS.LOG_SURICATA .. " 2>/dev/null")
    for line in lines:gmatch("[^\n]+") do
        local ok, event = pcall(json.parse, line)
        if ok and event and event.event_type == "alert" then
            table.insert(alerts, {
                timestamp = event.timestamp,
                signature = event.alert and event.alert.signature or "Unknown",
                src_ip = event.src_ip,
                src_port = event.src_port,
                dest_ip = event.dest_ip,
                dest_port = event.dest_port,
                severity = event.alert and event.alert.severity or 0
            })
        end
    end
    
    -- 只返回最后50条
    local result = {}
    local start = math.max(1, #alerts - 49)
    for i = #alerts, start, -1 do
        table.insert(result, alerts[i])
    end
    
    json_response({alerts = result})
end

-- API: 流量统计
function api_traffic_stats()
    local json = require "luci.jsonc"
    
    -- 尝试读取缓存
    if file_exists(PATHS.TRAFFIC_CACHE) then
        local content = read_file(PATHS.TRAFFIC_CACHE)
        if content then
            local ok, cached = pcall(json.parse, content)
            if ok and cached and cached.timestamp then
                -- 缓存有效期60秒
                if os.time() - cached.timestamp < 60 then
                    json_response(cached)
                    return
                end
            end
        end
    end
    
    local stats = {
        timestamp = os.time(),
        total_flows = 0,
        dns_queries = 0,
        http_requests = 0,
        tls_connections = 0,
        top_talkers = {},
        top_domains = {},
        top_ports = {},
        protocols = {}
    }
    
    if not file_exists(PATHS.LOG_SURICATA) then
        json_response(stats)
        return
    end
    
    local talkers, domains, ports, protos = {}, {}, {}, {}
    
    -- 使用tail限制读取行数
    local lines = exec_cmd("tail -10000 " .. PATHS.LOG_SURICATA .. " 2>/dev/null")
    for line in lines:gmatch("[^\n]+") do
        local ok, event = pcall(json.parse, line)
        if ok and event then
            local etype = event.event_type
            
            if etype == "flow" then
                stats.total_flows = stats.total_flows + 1
                local src = event.src_ip
                if src then
                    talkers[src] = talkers[src] or {bytes_in = 0, bytes_out = 0, flows = 0}
                    talkers[src].flows = talkers[src].flows + 1
                    if event.flow then
                        talkers[src].bytes_in = talkers[src].bytes_in + (event.flow.bytes_toclient or 0)
                        talkers[src].bytes_out = talkers[src].bytes_out + (event.flow.bytes_toserver or 0)
                    end
                end
                
                local proto = event.proto or "OTHER"
                protos[proto] = (protos[proto] or 0) + 1
                
                local dport = event.dest_port
                if dport then
                    ports[dport] = ports[dport] or {count = 0, proto = proto}
                    ports[dport].count = ports[dport].count + 1
                end
                
            elseif etype == "dns" then
                stats.dns_queries = stats.dns_queries + 1
                if event.dns and event.dns.rrname then
                    local domain = event.dns.rrname
                    domains[domain] = domains[domain] or {count = 0, type = event.dns.rrtype or "A"}
                    domains[domain].count = domains[domain].count + 1
                end
                
            elseif etype == "http" then
                stats.http_requests = stats.http_requests + 1
                
            elseif etype == "tls" then
                stats.tls_connections = stats.tls_connections + 1
            end
        end
    end
    
    -- 排序并获取Top 10
    local function get_top(t, key, limit)
        local sorted = {}
        for k, v in pairs(t) do
            table.insert(sorted, {key = k, value = v})
        end
        table.sort(sorted, function(a, b)
            local av = type(a.value) == "table" and (a.value[key] or a.value.count or 0) or a.value
            local bv = type(b.value) == "table" and (b.value[key] or b.value.count or 0) or b.value
            return av > bv
        end)
        local result = {}
        for i = 1, math.min(limit, #sorted) do
            table.insert(result, sorted[i])
        end
        return result
    end
    
    for _, t in ipairs(get_top(talkers, "flows", 10)) do
        table.insert(stats.top_talkers, {
            ip = t.key, bytes_in = t.value.bytes_in,
            bytes_out = t.value.bytes_out, flows = t.value.flows
        })
    end
    
    for _, d in ipairs(get_top(domains, "count", 10)) do
        table.insert(stats.top_domains, {
            domain = d.key, count = d.value.count, type = d.value.type
        })
    end
    
    for _, p in ipairs(get_top(ports, "count", 10)) do
        table.insert(stats.top_ports, {
            port = p.key, proto = p.value.proto,
            count = p.value.count, service = SERVICES[tonumber(p.key)]
        })
    end
    
    stats.protocols = protos
    
    -- 保存缓存
    local fs = require "nixio.fs"
    fs.mkdirr("/tmp/fwx")
    fs.writefile(PATHS.TRAFFIC_CACHE, json.stringify(stats))
    
    json_response(stats)
end

-- API: 通知测试
function api_notify_test()
    local ntype = luci.http.formvalue("type")
    
    if ntype ~= "email" and ntype ~= "webhook" then
        json_response({success = false, message = "Invalid type"})
        return
    end
    
    local ret = call_cmd("/usr/bin/fwx-notify test-" .. ntype .. " 2>&1")
    json_response({
        success = ret == 0,
        message = ret == 0 and ("Test " .. ntype .. " sent") or (ntype .. " send failed")
    })
end

-- API: 通知历史
function api_notify_history()
    local history = {}
    
    if file_exists(PATHS.LOG_NOTIFY) then
        for line in io.lines(PATHS.LOG_NOTIFY) do
            local time, ntype, status, detail = line:match("^%[([^%]]+)%]%s+(%w+)%s+(%w+)%s*(.*)")
            if time and #history < 50 then
                table.insert(history, 1, {
                    time = time, type = ntype, status = status, detail = detail or ""
                })
            end
        end
    end
    
    json_response({history = history})
end

-- API: 硬件检测和安全档位推荐
function api_hardware_profile()
    local ubus = require "ubus"
    local conn = ubus.connect()
    
    if not conn then
        json_response({error = "ubus connection failed"})
        return
    end
    
    local result = conn:call("fwx.security", "hardware_profile", {})
    conn:close()
    
    if result then
        json_response(result)
    else
        -- 降级方案：直接读取系统信息
        local fs = require "nixio.fs"
        local sys = require "luci.sys"
        
        local meminfo = fs.readfile("/proc/meminfo") or ""
        local mem_total = tonumber(meminfo:match("MemTotal:%s*(%d+)")) or 0
        mem_total = math.floor(mem_total / 1024)
        
        local cpuinfo = fs.readfile("/proc/cpuinfo") or ""
        local cpu_cores = 0
        for _ in cpuinfo:gmatch("processor") do
            cpu_cores = cpu_cores + 1
        end
        if cpu_cores == 0 then cpu_cores = 1 end
        
        -- 简单推荐逻辑
        local recommended = 0
        if mem_total >= 1024 and cpu_cores >= 4 then
            recommended = 4  -- maximum
        elseif mem_total >= 512 and cpu_cores >= 2 then
            recommended = 3  -- advanced
        elseif mem_total >= 256 and cpu_cores >= 2 then
            recommended = 2  -- standard
        elseif mem_total >= 128 then
            recommended = 1  -- basic
        end
        
        json_response({
            hardware = {
                memory_total_mb = mem_total,
                cpu_cores = cpu_cores
            },
            recommended_level = recommended,
            profiles = {
                {level = 0, name = "minimal", display_name = "最小防护", min_memory_mb = 64},
                {level = 1, name = "basic", display_name = "基础防护", min_memory_mb = 128},
                {level = 2, name = "standard", display_name = "标准防护", min_memory_mb = 256},
                {level = 3, name = "advanced", display_name = "高级防护", min_memory_mb = 512},
                {level = 4, name = "maximum", display_name = "最大防护", min_memory_mb = 1024}
            }
        })
    end
end

-- API: 应用安全档位
function api_apply_profile()
    local level = tonumber(luci.http.formvalue("level"))
    
    if not level or level < 0 or level > 4 then
        json_response({success = false, message = "Invalid profile level"})
        return
    end
    
    local ubus = require "ubus"
    local conn = ubus.connect()
    
    if conn then
        local result = conn:call("fwx.security", "apply_profile", {level = level})
        conn:close()
        
        if result and result.code == 0 then
            json_response({success = true, message = result.message, profile = result.profile})
        else
            json_response({success = false, message = result and result.message or "Apply failed"})
        end
    else
        json_response({success = false, message = "ubus connection failed"})
    end
end
