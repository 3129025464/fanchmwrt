local m, s, o
m = Map("fwx_ipsec", translate("IPSec VPN"), translate("Site-to-site VPN"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

s = m:section(TypedSection, "tunnel", translate("Tunnels"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "remote_gateway", translate("Remote Gateway"))
o.datatype = "host"

o = s:option(Value, "local_subnet", translate("Local Subnet"))
o.datatype = "cidr4"

o = s:option(Value, "remote_subnet", translate("Remote Subnet"))
o.datatype = "cidr4"

o = s:option(Value, "psk", translate("Pre-Shared Key"))
o.password = true

return m
