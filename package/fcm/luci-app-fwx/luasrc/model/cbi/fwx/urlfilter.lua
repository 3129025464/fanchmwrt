local m, s, o
m = Map("fwx_urlfilter", translate("URL Filter"), translate("Domain blocking"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Flag, "safe_search", translate("Safe Search"))
o.default = "0"

s = m:section(TypedSection, "category", translate("Categories"))
s.anonymous = false
s.addremove = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "name", translate("Name"))

o = s:option(Value, "url", translate("List URL"))

return m
