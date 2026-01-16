/**
 * FanchMWRT Security Center - Common JavaScript
 */

var FWX = FWX || {};

// API基础路径
FWX.apiBase = null;

// 初始化
FWX.init = function(baseUrl) {
    FWX.apiBase = baseUrl;
};

// 通用API调用
FWX.api = {
    get: function(endpoint, callback) {
        XHR.get(FWX.apiBase + endpoint, null, function(x, data) {
            callback(data);
        });
    },
    
    post: function(endpoint, params, callback) {
        XHR.post(FWX.apiBase + endpoint, params, function(x, data) {
            callback(data);
        });
    }
};

// 格式化工具
FWX.format = {
    number: function(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    },
    
    bytes: function(bytes) {
        if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return bytes + ' B';
    },
    
    escape: function(str) {
        return str ? str.replace(/</g, '&lt;').replace(/>/g, '&gt;') : '';
    }
};

// DOM工具
FWX.dom = {
    setText: function(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    },
    
    setHtml: function(id, html) {
        var el = document.getElementById(id);
        if (el) el.innerHTML = html;
    },
    
    setClass: function(id, className) {
        var el = document.getElementById(id);
        if (el) el.className = className;
    },
    
    getValue: function(id) {
        var el = document.getElementById(id);
        return el ? el.value : '';
    }
};

// 状态指示器
FWX.status = {
    setDot: function(id, running) {
        FWX.dom.setClass(id, 'fwx-status-dot ' + (running ? 'running' : 'stopped'));
    },
    
    setValue: function(id, value, state) {
        var el = document.getElementById(id);
        if (el) {
            el.textContent = value;
            el.className = 'value' + (state ? ' ' + state : '');
        }
    }
};

// 表格渲染
FWX.table = {
    render: function(containerId, headers, rows, emptyMsg) {
        var container = document.getElementById(containerId);
        if (!container) return;
        
        if (!rows || rows.length === 0) {
            container.innerHTML = '<em>' + (emptyMsg || 'No data') + '</em>';
            return;
        }
        
        var html = '<table class="alerts-table"><thead><tr>';
        headers.forEach(function(h) {
            html += '<th>' + h + '</th>';
        });
        html += '</tr></thead><tbody>';
        
        rows.forEach(function(row) {
            html += '<tr>';
            row.forEach(function(cell) {
                html += '<td>' + FWX.format.escape(String(cell)) + '</td>';
            });
            html += '</tr>';
        });
        
        html += '</tbody></table>';
        container.innerHTML = html;
    }
};

// 定时刷新
FWX.refresh = {
    timers: {},
    
    start: function(name, fn, interval) {
        FWX.refresh.stop(name);
        fn(); // 立即执行一次
        FWX.refresh.timers[name] = setInterval(fn, interval);
    },
    
    stop: function(name) {
        if (FWX.refresh.timers[name]) {
            clearInterval(FWX.refresh.timers[name]);
            delete FWX.refresh.timers[name];
        }
    },
    
    stopAll: function() {
        for (var name in FWX.refresh.timers) {
            FWX.refresh.stop(name);
        }
    }
};

// 消息提示
FWX.msg = {
    show: function(id, text, isError) {
        var el = document.getElementById(id);
        if (el) {
            el.textContent = text;
            el.style.color = isError ? 'var(--error-color-high)' : '';
        }
    }
};
