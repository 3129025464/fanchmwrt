-- FWX Alert Notification Configuration
-- Copyright (c) 2026 FanchMWRT

local m, s, o

m = Map("fwx_notify", translate("Alert Notifications"),
    translate("Configure email and webhook notifications for security alerts."))

-- Global settings
s = m:section(NamedSection, "global", "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Notifications"))
o.rmempty = false
o.default = "0"

o = s:option(ListValue, "min_level", translate("Minimum Alert Level"))
o.description = translate("Only send notifications for alerts at or above this level")
o:value("info", translate("Info"))
o:value("warning", translate("Warning"))
o:value("critical", translate("Critical"))
o:value("emergency", translate("Emergency"))
o.default = "warning"

o = s:option(Value, "rate_limit", translate("Rate Limit (per hour)"))
o.description = translate("Maximum notifications per hour (0 = unlimited)")
o.datatype = "uinteger"
o.default = "10"

o = s:option(Flag, "aggregate", translate("Aggregate Alerts"))
o.description = translate("Combine multiple alerts into single notification")
o.rmempty = false
o.default = "1"

o = s:option(Value, "aggregate_interval", translate("Aggregate Interval (minutes)"))
o:depends("aggregate", "1")
o.datatype = "uinteger"
o.default = "5"

-- Email Settings
s = m:section(NamedSection, "email", "email", translate("Email Notifications"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Email"))
o.rmempty = false
o.default = "0"

o = s:option(Value, "smtp_server", translate("SMTP Server"))
o:depends("enable", "1")
o.placeholder = "smtp.example.com"

o = s:option(Value, "smtp_port", translate("SMTP Port"))
o:depends("enable", "1")
o.datatype = "port"
o.default = "587"

o = s:option(ListValue, "smtp_security", translate("Security"))
o:depends("enable", "1")
o:value("none", translate("None"))
o:value("starttls", "STARTTLS")
o:value("ssl", "SSL/TLS")
o.default = "starttls"

o = s:option(Value, "smtp_user", translate("Username"))
o:depends("enable", "1")

o = s:option(Value, "smtp_pass", translate("Password"))
o:depends("enable", "1")
o.password = true

o = s:option(Value, "from_addr", translate("From Address"))
o:depends("enable", "1")
o.placeholder = "alert@example.com"

o = s:option(DynamicList, "to_addr", translate("To Addresses"))
o:depends("enable", "1")
o.datatype = "email"

o = s:option(Value, "subject_prefix", translate("Subject Prefix"))
o:depends("enable", "1")
o.default = "[FanchMWRT Alert]"

-- Webhook Settings
s = m:section(NamedSection, "webhook", "webhook", translate("Webhook Notifications"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable Webhook"))
o.rmempty = false
o.default = "0"

o = s:option(Value, "url", translate("Webhook URL"))
o:depends("enable", "1")
o.placeholder = "https://hooks.example.com/alert"

o = s:option(ListValue, "method", translate("HTTP Method"))
o:depends("enable", "1")
o:value("POST", "POST")
o:value("PUT", "PUT")
o.default = "POST"

o = s:option(ListValue, "format", translate("Payload Format"))
o:depends("enable", "1")
o:value("json", "JSON")
o:value("slack", "Slack")
o:value("discord", "Discord")
o:value("telegram", "Telegram")
o:value("custom", translate("Custom"))
o.default = "json"

o = s:option(Value, "telegram_token", translate("Telegram Bot Token"))
o:depends("format", "telegram")

o = s:option(Value, "telegram_chat_id", translate("Telegram Chat ID"))
o:depends("format", "telegram")

o = s:option(TextValue, "custom_template", translate("Custom Template"))
o:depends("format", "custom")
o.rows = 6
o.description = translate("Use {{level}}, {{type}}, {{src}}, {{dst}}, {{detail}}, {{time}} placeholders")

o = s:option(DynamicList, "headers", translate("Custom Headers"))
o:depends("enable", "1")
o.description = translate("Format: Header-Name: value")

o = s:option(Value, "timeout", translate("Timeout (seconds)"))
o:depends("enable", "1")
o.datatype = "uinteger"
o.default = "10"

o = s:option(Flag, "verify_ssl", translate("Verify SSL Certificate"))
o:depends("enable", "1")
o.rmempty = false
o.default = "1"

-- Alert Types
s = m:section(NamedSection, "types", "types", translate("Alert Types"))
s.anonymous = true
s.addremove = false
s.description = translate("Select which alert types to send notifications for")

o = s:option(Flag, "threat_ip", translate("Threat IP Blocked"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "threat_domain", translate("Threat Domain Blocked"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "portscan", translate("Port Scan Detected"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "synflood", translate("SYN Flood Detected"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "bruteforce", translate("Brute Force Detected"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "malware", translate("Malware Detected"))
o.rmempty = false
o.default = "1"

o = s:option(Flag, "suricata", translate("Suricata Alerts"))
o.rmempty = false
o.default = "1"

-- Test
s = m:section(SimpleSection)
s.template = "fwx/notify_test"

return m
