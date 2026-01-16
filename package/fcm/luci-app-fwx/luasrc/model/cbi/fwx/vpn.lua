local m, s, o
m = Map("fwx_vpn", translate("WireGuard VPN"), translate("VPN server"))

s = m:section(NamedSection, "server", "server", translate("Server"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "port", translate("Port"))
o.datatype = "port"
o.default = "51820"

o = s:option(Value, "address", translate("Address"))
o.default = "10.10.10.1/24"

o = s:option(Value, "dns", translate("DNS"))
o.default = "8.8.8.8"

o = s:option(Value, "public_key", translate("Public Key"))
o.readonly = true

s = m:section(TypedSection, "client", translate("Clients"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "public_key", translate("Public Key"))
o.readonly = true

o = s:option(Value, "allowed_ips", translate("Allowed IPs"))

return m
