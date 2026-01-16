-- FWX Global Settings
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx", translate("FWX Settings"),
    translate("Global settings for FanchMWRT security system."))

-- 安全档位
s = m:section(NamedSection, "security", "security", translate("Security Profile"))
s.anonymous = true
s.addremove = false
s.description = translate("Select security protection level based on your device capabilities.")

-- 安全档位选择模板
s = m:section(SimpleSection)
s.template = "fwx/security_profile"

-- Global settings
s = m:section(NamedSection, "global", "global", translate("General"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "lan_ifname", translate("LAN Interface"))
o.default = "br-lan"

o = s:option(ListValue, "theme_mode", translate("Theme Mode"))
o:value("0", translate("Light"))
o:value("1", translate("Dark"))
o:value("2", translate("Auto"))
o.default = "1"

-- Alert settings
s = m:section(NamedSection, "alert", "alert", translate("Alert Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Alerts"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "log_file", translate("Log File"))
o.default = "/tmp/log/fwx-security.log"

o = s:option(Value, "max_log_size", translate("Max Log Size (KB)"))
o.datatype = "uinteger"
o.default = "1024"

-- Record settings
s = m:section(NamedSection, "record", "record", translate("Record Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Recording"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "record_time", translate("Record Time (days)"))
o.datatype = "uinteger"
o.default = "3"

o = s:option(Value, "history_data_size", translate("History Size (MB)"))
o.datatype = "uinteger"
o.default = "10"

o = s:option(Value, "history_data_path", translate("History Path"))
o.default = "/tmp/fwx"

return m
