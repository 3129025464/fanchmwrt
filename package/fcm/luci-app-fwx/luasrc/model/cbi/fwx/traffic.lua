-- FWX Traffic Analysis Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx_traffic", translate("Traffic Analysis"),
    translate("Network traffic statistics and analysis based on Suricata EVE logs."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Traffic Analysis"))
o.rmempty = false
o.default = "1"

o = s:option(Value, "eve_log_path", translate("EVE Log Path"))
o.default = "/tmp/log/suricata/eve.json"

o = s:option(Value, "stats_interval", translate("Statistics Interval (seconds)"))
o.datatype = "uinteger"
o.default = "60"

o = s:option(Value, "retention_days", translate("Data Retention (days)"))
o.datatype = "uinteger"
o.default = "7"

-- Protocol Statistics
s = m:section(NamedSection, "protocols", "protocols", translate("Protocol Statistics"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "dns_stats", translate("DNS Statistics"))
o.description = translate("Track DNS queries and responses")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "http_stats", translate("HTTP Statistics"))
o.description = translate("Track HTTP requests and responses")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "tls_stats", translate("TLS Statistics"))
o.description = translate("Track TLS/SSL connections")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "flow_stats", translate("Flow Statistics"))
o.description = translate("Track network flows")
o.rmempty = false
o.default = "1"

-- Top N Settings
s = m:section(NamedSection, "topn", "topn", translate("Top N Statistics"))
s.anonymous = true
s.addremove = false

o = s:option(Value, "top_count", translate("Top N Count"))
o.datatype = "uinteger"
o.default = "10"

o = s:option(Flag, "top_talkers", translate("Top Talkers"))
o.description = translate("Track hosts with most traffic")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "top_domains", translate("Top Domains"))
o.description = translate("Track most queried domains")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "top_ports", translate("Top Ports"))
o.description = translate("Track most used ports")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "top_apps", translate("Top Applications"))
o.description = translate("Track most used applications")
o.rmempty = false
o.default = "1"

-- Anomaly Detection
s = m:section(NamedSection, "anomaly", "anomaly", translate("Anomaly Detection"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Anomaly Detection"))
o.rmempty = false
o.default = "0"

o = s:option(Value, "baseline_days", translate("Baseline Period (days)"))
o.description = translate("Days of data to establish baseline")
o:depends("enable", "1")
o.datatype = "uinteger"
o.default = "7"

o = s:option(Value, "threshold", translate("Anomaly Threshold (%)"))
o.description = translate("Deviation percentage to trigger alert")
o:depends("enable", "1")
o.datatype = "uinteger"
o.default = "200"

o = s:option(Flag, "alert_bandwidth", translate("Bandwidth Anomalies"))
o:depends("enable", "1")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "alert_connections", translate("Connection Anomalies"))
o:depends("enable", "1")
o.rmempty = false
o.default = "1"

o = s:option(Flag, "alert_dns", translate("DNS Anomalies"))
o:depends("enable", "1")
o.rmempty = false
o.default = "1"

-- Dashboard
s = m:section(SimpleSection)
s.template = "fwx/traffic_dashboard"

return m
