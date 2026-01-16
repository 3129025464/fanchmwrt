-- FWX Antivirus Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx_av", translate("Antivirus"),
    translate("ClamAV integration for malware scanning."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false
o.default = "0"

o = s:option(Flag, "auto_update", translate("Auto Update Database"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "update_interval", translate("Update Interval (hours)"))
o.datatype = "uinteger"
o.default = "24"

-- Scan settings
s = m:section(NamedSection, "scan", "scan", translate("Scan Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "realtime_enable", translate("Realtime Scanning"))
o.description = translate("Monitor directories for new files (requires inotify-tools)")
o.rmempty = false
o.default = "0"

o = s:option(Value, "realtime_paths", translate("Realtime Scan Paths"))
o.description = translate("Space-separated list of directories to monitor")
o:depends("realtime_enable", "1")
o.default = "/tmp/upload /www/upload"

o = s:option(Value, "max_file_size", translate("Max File Size (MB)"))
o.datatype = "uinteger"
o.default = "25"

o = s:option(Flag, "scan_archives", translate("Scan Archives"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "quarantine_path", translate("Quarantine Path"))
o.default = "/etc/fwx/av/quarantine"

-- Scheduled scan
s = m:section(NamedSection, "schedule", "schedule", translate("Scheduled Scan"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Scheduled Scan"))
o.rmempty = false
o.default = "0"

o = s:option(Value, "scan_path", translate("Scan Path"))
o:depends("enable", "1")
o.default = "/tmp"

o = s:option(Value, "scan_time", translate("Scan Time"))
o.description = translate("Time in HH:MM format")
o:depends("enable", "1")
o.default = "03:00"

-- Action settings
s = m:section(NamedSection, "action", "action", translate("Detection Action"))
s.anonymous = true
s.addremove = false

o = s:option(ListValue, "on_detect", translate("On Detection"))
o:value("quarantine", translate("Quarantine"))
o:value("delete", translate("Delete"))
o:value("log", translate("Log Only"))
o.default = "quarantine"

o = s:option(Flag, "alert_enable", translate("Send Alert"))
o.rmempty = false
o.default = "1"

-- Manual actions
s = m:section(SimpleSection)
s.template = "fwx/av_actions"

return m
