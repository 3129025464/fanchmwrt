local m, s, o
m = Map("fwx_ha", translate("High Availability"), translate("VRRP failover"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "priority", translate("Priority"))
o.datatype = "range(1,255)"
o.default = "100"

o = s:option(Flag, "preempt", translate("Preempt"))
o.default = "1"

s = m:section(NamedSection, "vrrp", "vrrp", translate("VRRP"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "interface", translate("Interface"))
o.default = "lan"

o = s:option(Value, "virtual_router_id", translate("Router ID"))
o.datatype = "range(1,255)"
o.default = "51"

o = s:option(DynamicList, "virtual_ip", translate("Virtual IPs"))
o.datatype = "cidr4"

o = s:option(Value, "auth_pass", translate("Password"))
o.password = true
o.default = "fwxha123"

s = m:section(NamedSection, "peer", "peer", translate("Peer"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "address", translate("Peer Address"))
o.datatype = "ip4addr"

return m
