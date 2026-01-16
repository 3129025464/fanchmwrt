-- FWX Threat Intelligence Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("threat_intel", translate("Threat Intelligence"),
    translate("Configure threat intelligence sources and blacklist settings."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "auto_update", translate("Auto Update"))
o.description = translate("Automatically update threat lists")
o.rmempty = false
o.default = "1"

o = s:option(Value, "update_interval", translate("Update Interval (hours)"))
o.datatype = "uinteger"
o.default = "24"

o = s:option(Flag, "log_blocked", translate("Log Blocked"))
o.description = translate("Log blocked connections")
o.rmempty = false
o.default = "1"

o = s:option(ListValue, "action", translate("Action"))
o:value("drop", translate("Drop"))
o:value("reject", translate("Reject"))
o.default = "drop"

-- Threat Sources
s = m:section(TypedSection, "source", translate("Threat Sources"))
s.anonymous = false
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.width = "10%"

o = s:option(Value, "name", translate("Name"))
o.rmempty = false
o.width = "20%"

o = s:option(ListValue, "type", translate("Type"))
o:value("ip", translate("IP Blacklist"))
o:value("domain", translate("Domain Blacklist"))
o.width = "15%"

o = s:option(Value, "url", translate("URL"))
o.rmempty = false
o.width = "40%"

o = s:option(ListValue, "format", translate("Format"))
o:value("plain", translate("Plain Text"))
o:value("hosts", translate("Hosts File"))
o:value("spamhaus", translate("Spamhaus"))
o.width = "15%"

-- Whitelist
s = m:section(NamedSection, "whitelist", "whitelist", translate("Whitelist"))
s.anonymous = true
s.addremove = false

o = s:option(DynamicList, "ip", translate("IP Whitelist"))
o.datatype = "ipaddr"
o.description = translate("IPs that should never be blocked")

o = s:option(DynamicList, "domain", translate("Domain Whitelist"))
o.description = translate("Domains that should never be blocked")

-- Manual update button
s = m:section(SimpleSection)
s.template = "fwx/threat_actions"

return m
