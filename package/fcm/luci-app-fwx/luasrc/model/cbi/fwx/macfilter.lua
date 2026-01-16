-- FWX MAC Filter Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("macfilter", translate("MAC Filter"),
    translate("Filter network access by MAC address."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

-- MAC rules would be managed via user_info config
-- This is a placeholder for the basic structure

s = m:section(SimpleSection)
s.template = "fwx/macfilter_info"

return m
