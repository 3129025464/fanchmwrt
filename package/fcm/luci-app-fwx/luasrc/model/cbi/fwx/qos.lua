local m, s, o
m = Map("fwx_qos", translate("QoS"), translate("Bandwidth management"))

s = m:section(NamedSection, "global", "global", translate("Settings"))
s.anonymous = true

o = s:option(Flag, "enable", translate("Enable"))
o.default = "0"

o = s:option(Value, "download_bandwidth", translate("Download (kbps)"))
o.datatype = "uinteger"
o.default = "100000"

o = s:option(Value, "upload_bandwidth", translate("Upload (kbps)"))
o.datatype = "uinteger"
o.default = "50000"

o = s:option(ListValue, "qdisc", translate("Qdisc"))
o:value("cake", "CAKE")
o:value("htb", "HTB")
o.default = "cake"

return m
