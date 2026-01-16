'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';

return view.extend({
    load: function() {
        return Promise.all([
            uci.load('fwx_dpi'),
            fs.exec('/usr/bin/fwx-dpi', ['protocols']).catch(function() { return { stdout: '' }; }),
            fs.exec('/usr/bin/fwx-dpi', ['stats']).catch(function() { return { stdout: '{}' }; })
        ]);
    },

    render: function(data) {
        var protocols = data[1].stdout.split(/\s+/).filter(function(p) { return p.length > 0; });
        var stats = {};
        try {
            stats = JSON.parse(data[2].stdout);
        } catch(e) {}

        var m, s, o;

        m = new form.Map('fwx_dpi', _('Deep Packet Inspection'),
            _('Application identification and control using nDPI'));

        // Global settings
        s = m.section(form.TypedSection, 'global', _('Global Settings'));
        s.anonymous = true;

        o = s.option(form.Flag, 'enable', _('Enable DPI'));
        o.rmempty = false;

        o = s.option(form.Flag, 'log_enable', _('Enable Logging'));
        o.default = '1';

        o = s.option(form.Flag, 'stats_enable', _('Enable Statistics'));
        o.default = '1';

        o = s.option(form.Value, 'stats_interval', _('Statistics Interval (seconds)'));
        o.datatype = 'uinteger';
        o.default = '60';

        // Application Categories
        s = m.section(form.GridSection, 'category', _('Application Categories'));
        s.addremove = true;
        s.anonymous = true;
        s.sortable = true;

        o = s.option(form.Value, 'name', _('Category Name'));
        o.rmempty = false;

        o = s.option(form.DynamicList, 'apps', _('Applications'));
        o.rmempty = false;

        o = s.option(form.ListValue, 'action', _('Action'));
        o.value('accept', _('Accept'));
        o.value('drop', _('Drop'));
        o.value('mark', _('Mark (for QoS)'));
        o.default = 'accept';

        o = s.option(form.Value, 'mark', _('Mark Value'));
        o.datatype = 'uinteger';
        o.depends('action', 'mark');

        o = s.option(form.ListValue, 'priority', _('Priority'));
        o.value('', _('Normal'));
        o.value('high', _('High'));
        o.value('low', _('Low'));
        o.depends('action', 'accept');

        // Custom Rules
        s = m.section(form.GridSection, 'rule', _('Custom Rules'));
        s.addremove = true;
        s.anonymous = true;

        o = s.option(form.Value, 'name', _('Rule Name'));
        o.rmempty = false;

        o = s.option(form.DynamicList, 'apps', _('Applications'));
        o.rmempty = false;

        o = s.option(form.ListValue, 'action', _('Action'));
        o.value('accept', _('Accept'));
        o.value('drop', _('Drop'));
        o.default = 'drop';

        o = s.option(form.Flag, 'log', _('Log Matches'));
        o.default = '0';

        return m.render();
    }
});
