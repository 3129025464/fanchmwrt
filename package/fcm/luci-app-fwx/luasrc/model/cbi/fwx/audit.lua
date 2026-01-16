local m, s, o
m = Map("fwx_audit", translate("Log Audit"), translate("Logging and SIEM"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "log_retention", translate("Retention (days)"))
o.datatype = "uinteger"
o.default = "30"

s = m:section(TypedSection, "remote", translate("Remote Syslog"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "host", translate("Host"))
o.datatype = "host"

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"
o.default = "514"

o = s:option(ListValue, "protocol", translate("Protocol"))
o:value("udp", "UDP")
o:value("tcp", "TCP")
o.default = "udp"

return m
