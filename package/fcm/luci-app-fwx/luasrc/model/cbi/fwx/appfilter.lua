-- FWX App Filter Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("appfilter", translate("Application Filter"),
    translate("Filter network traffic by application."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "1"

o = s:option(ListValue, "work_mode", translate("Work Mode"))
o:value("0", translate("Gateway Mode"))
o:value("1", translate("Bypass Mode"))
o:value("2", translate("Bridge Mode"))
o.default = "0"

o = s:option(Flag, "record_enable", translate("Enable Recording"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "lan_ifname", translate("LAN Interface"))
o.default = "br-lan"

-- Feature update
s = m:section(NamedSection, "feature", "feature", translate("Feature Database"))
s.anonymous = true
s.addremove = false

o = s:option(DummyValue, "format", translate("Format Version"))

o = s:option(DummyValue, "_info", translate("Info"))
o.rawhtml = true
o.cfgvalue = function()
    local fs = require "nixio.fs"
    local cfg_file = "/etc/fwxd/feature.cfg"
    if fs.access(cfg_file) then
        local count = 0
        for _ in io.lines(cfg_file) do count = count + 1 end
        return string.format("<em>%s: %d %s</em>", 
            translate("Feature file"), count, translate("lines"))
    end
    return "<em>" .. translate("Feature file not found") .. "</em>"
end

return m
