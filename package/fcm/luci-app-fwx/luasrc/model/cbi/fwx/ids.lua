-- FWX IDS/IPS Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx_ids", translate("Intrusion Detection System"),
    translate("Configure IDS/IPS settings for network protection."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable IDS"))
o.rmempty = false
o.default = "1"

o = s:option(ListValue, "log_level", translate("Log Level"))
o:value("error", translate("Error"))
o:value("warn", translate("Warning"))
o:value("info", translate("Info"))
o:value("debug", translate("Debug"))
o.default = "info"

-- Port Scan Detection
s = m:section(NamedSection, "portscan", "portscan", translate("Port Scan Detection"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "threshold", translate("Threshold"))
o.description = translate("Number of ports scanned before triggering")
o.datatype = "uinteger"
o.default = "20"

o = s:option(Value, "interval", translate("Interval (seconds)"))
o.datatype = "uinteger"
o.default = "60"

o = s:option(ListValue, "action", translate("Action"))
o:value("log", translate("Log Only"))
o:value("block", translate("Block"))
o.default = "block"

o = s:option(Value, "block_time", translate("Block Time (seconds)"))
o.datatype = "uinteger"
o.default = "3600"

-- SYN Flood Protection
s = m:section(NamedSection, "synflood", "synflood", translate("SYN Flood Protection"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "rate", translate("Rate Limit (per second)"))
o.datatype = "uinteger"
o.default = "25"

o = s:option(Value, "burst", translate("Burst"))
o.datatype = "uinteger"
o.default = "50"

o = s:option(ListValue, "action", translate("Action"))
o:value("drop", translate("Drop"))
o:value("reject", translate("Reject"))
o.default = "drop"

-- Brute Force Protection
s = m:section(NamedSection, "bruteforce", "bruteforce", translate("Brute Force Protection"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "ssh_enable", translate("SSH Protection"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "ssh_max_retry", translate("SSH Max Retries"))
o.datatype = "uinteger"
o.default = "5"

o = s:option(Value, "ssh_block_time", translate("SSH Block Time (seconds)"))
o.datatype = "uinteger"
o.default = "3600"

o = s:option(Flag, "web_enable", translate("Web Protection"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "web_max_retry", translate("Web Max Retries"))
o.datatype = "uinteger"
o.default = "10"

-- ICMP Flood Protection
s = m:section(NamedSection, "icmpflood", "icmpflood", translate("ICMP Flood Protection"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "rate", translate("Rate Limit (per second)"))
o.datatype = "uinteger"
o.default = "10"

o = s:option(Value, "burst", translate("Burst"))
o.datatype = "uinteger"
o.default = "20"

-- Blocked IPs section
s = m:section(SimpleSection)
s.template = "fwx/ids_blocked"

return m
