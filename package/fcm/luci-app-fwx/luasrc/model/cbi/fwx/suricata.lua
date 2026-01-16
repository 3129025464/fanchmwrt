-- FWX Suricata Deep IDS Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx_suricata", translate("Suricata Deep IDS"),
    translate("Advanced intrusion detection with Suricata engine."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Suricata"))
o.rmempty = false
o.default = "0"

o = s:option(ListValue, "mode", translate("Run Mode"))
o:value("ids", translate("IDS - Detection Only"))
o:value("ips", translate("IPS - Inline Prevention"))
o.default = "ids"

o = s:option(Value, "interface", translate("Monitor Interface"))
o.default = "br-lan"

o = s:option(Value, "home_net", translate("Home Network"))
o.description = translate("CIDR notation, e.g. 192.168.1.0/24")
o.default = "192.168.1.0/24"

o = s:option(ListValue, "log_level", translate("Log Level"))
o:value("emergency", "Emergency")
o:value("alert", "Alert")
o:value("error", "Error")
o:value("warning", "Warning")
o:value("notice", "Notice")
o:value("info", "Info")
o:value("debug", "Debug")
o.default = "info"

-- Performance
s = m:section(NamedSection, "performance", "performance", translate("Performance"))
s.anonymous = true
s.addremove = false

o = s:option(ListValue, "runmode", translate("Threading Mode"))
o:value("single", translate("Single Thread"))
o:value("autofp", translate("Auto Flow Pinning"))
o:value("workers", translate("Workers"))
o.default = "autofp"

o = s:option(Value, "detect_threads", translate("Detection Threads"))
o.datatype = "uinteger"
o.default = "2"

o = s:option(Value, "stream_memcap", translate("Stream Memory Cap (MB)"))
o.datatype = "uinteger"
o.default = "32"

o = s:option(Value, "flow_memcap", translate("Flow Memory Cap (MB)"))
o.datatype = "uinteger"
o.default = "32"

-- Rule Sources
s = m:section(NamedSection, "rules", "rules", translate("Rule Sources"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "et_open", translate("Emerging Threats Open"))
o.description = translate("Free community ruleset")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "et_pro", translate("Emerging Threats Pro"))
o.description = translate("Commercial ruleset (requires subscription)")
o.rmempty = false
o.default = "0"

o = s:option(Value, "et_pro_code", translate("ET Pro Code"))
o:depends("et_pro", "1")

o = s:option(Flag, "snort_community", translate("Snort Community"))
o.rmempty = false
o.default = "0"

o = s:option(Flag, "abuse_sslbl", translate("Abuse.ch SSL Blacklist"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "custom_rules_url", translate("Custom Rules URL"))
o.description = translate("URL to custom rules file")

-- Rule Categories
s = m:section(NamedSection, "categories", "categories", translate("Rule Categories"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "malware", translate("Malware"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "exploit", translate("Exploits"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "scan", translate("Scanning"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "dos", translate("DoS Attacks"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "web_attack", translate("Web Attacks"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "trojan", translate("Trojans"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "botnet", translate("Botnets"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "policy", translate("Policy Violations"))
o.rmempty = false
o.default = "0"

-- EVE JSON Logging
s = m:section(NamedSection, "eve", "eve", translate("EVE JSON Logging"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable EVE Log"))
o.description = translate("JSON format logging for analysis")
o.rmempty = false
o.default = "1"

o = s:option(Value, "log_path", translate("Log Path"))
o.default = "/tmp/log/suricata/eve.json"

o = s:option(Flag, "log_alerts", translate("Log Alerts"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "log_dns", translate("Log DNS"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "log_http", translate("Log HTTP"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "log_tls", translate("Log TLS"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "log_flow", translate("Log Flows"))
o.rmempty = false
o.default = "0"

o = s:option(Flag, "log_stats", translate("Log Statistics"))
o.rmempty = false
o.default = "1"

-- Actions
s = m:section(SimpleSection)
s.template = "fwx/suricata_actions"

return m
