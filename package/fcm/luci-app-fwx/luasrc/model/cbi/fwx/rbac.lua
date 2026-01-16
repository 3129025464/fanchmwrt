local m, s, o
m = Map("fwx_rbac", translate("Access Control"), translate("User management"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

s = m:section(TypedSection, "user", translate("Users"))
s.anonymous = true
s.addremove = true
s.template = "cbi/tblsection"

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "username", translate("Username"))

o = s:option(Value, "password_hash", translate("Password"))
o.password = true

o = s:option(ListValue, "role", translate("Role"))
o:value("admin", translate("Administrator"))
o:value("security_admin", translate("Security Admin"))
o:value("network_admin", translate("Network Admin"))
o:value("monitor", translate("Monitor"))
o.default = "monitor"

return m
