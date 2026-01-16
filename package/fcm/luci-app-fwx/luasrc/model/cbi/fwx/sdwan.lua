local m, s, o
m = Map("fwx_sdwan", translate("SD-WAN"), translate("Multi-link load balancing"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

s = m:section(TypedSection, "interface", translate("WAN Interfaces"))
s.anonymous = false
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "ifname", translate("Interface"))

o = s:option(Value, "weight", translate("Weight"))
o.datatype = "range(1,10)"
o.default = "1"

o = s:option(Value, "track_ip", translate("Track IP"))
o.default = "8.8.8.8"

s = m:section(TypedSection, "policy", translate("Policies"))
s.anonymous = false
s.addremove = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(ListValue, "type", translate("Type"))
o:value("balance", translate("Load Balance"))
o:value("failover", translate("Failover"))
o.default = "balance"

o = s:option(DynamicList, "interface", translate("Interfaces"))

return m
