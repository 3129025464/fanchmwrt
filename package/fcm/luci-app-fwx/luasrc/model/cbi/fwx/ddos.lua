local m, s, o
m = Map("fwx_ddos", translate("DDoS Protection"), translate("Flood protection"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "syn_rate", translate("SYN Rate Limit"))
o.default = "50/second"

o = s:option(Value, "udp_rate", translate("UDP Rate Limit"))
o.default = "100/second"

o = s:option(Value, "icmp_rate", translate("ICMP Rate Limit"))
o.default = "10/second"

o = s:option(Value, "conn_limit", translate("Connection Limit"))
o.datatype = "uinteger"
o.default = "100"

o = s:option(Flag, "syncookie", translate("SYN Cookie"))
o.default = "1"

o = s:option(Flag, "auto_ban", translate("Auto Ban"))
o.default = "1"

o = s:option(Value, "ban_time", translate("Ban Time (seconds)"))
o.datatype = "uinteger"
o.default = "3600"

return m
