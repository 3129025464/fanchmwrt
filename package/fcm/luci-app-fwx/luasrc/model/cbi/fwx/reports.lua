local m, s, o
m = Map("fwx_reports", translate("Reports"), translate("Statistics and reports"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "1"

o = s:option(Value, "collect_interval", translate("Interval (seconds)"))
o.datatype = "uinteger"
o.default = "300"

return m
