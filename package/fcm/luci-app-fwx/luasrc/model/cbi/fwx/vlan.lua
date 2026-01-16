local m, s, o
m = Map("fwx_vlan", translate("VLAN"), translate("VLAN management"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

s = m:section(TypedSection, "vlan", translate("VLANs"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "vid", translate("VLAN ID"))
o.datatype = "range(1,4094)"

o = s:option(Value, "parent", translate("Parent"))
o.default = "eth0"

o = s:option(Value, "ipaddr", translate("IP Address"))
o.datatype = "ip4addr"

o = s:option(Value, "netmask", translate("Netmask"))
o.default = "255.255.255.0"

o = s:option(Flag, "dhcp", translate("DHCP"))
o.default = "1"

o = s:option(Flag, "isolate", translate("Isolate"))
o.default = "1"

return m
