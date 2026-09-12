
(function () {
    var ALIASES = window.__GW_ALIASES || {};
    var RULES = [['/netscope/api/', 'ns'], ['/get_chart_data', 'chart'],
                 ['/assistant/api/', 'chat'],
                 ['/notifications/api/', 'notify']];
    var hasAny = RULES.some(function (r) { return ALIASES[r[1]]; });
    if (!hasAny || typeof window.fetch !== 'function') return;

    var _origFetch = window.fetch;
    window.fetch = function (input, init) {
        try {
            var url = (typeof input === 'string') ? input : (input && input.url) || '';
            if (url.charAt(0) === '/') {
                for (var i = 0; i < RULES.length; i++) {
                    var prefix = RULES[i][0], key = RULES[i][1];
                    if (ALIASES[key] && url.indexOf(prefix) === 0) {
                        var opts = Object.assign({}, init || {});
                        var srcHeaders = (typeof input !== 'string' && input && input.headers)
                            ? input.headers : ((init && init.headers) || undefined);
                        var h = new Headers(srcHeaders);
                        h.set('X-GW-Path', url);
                        opts.headers = h;
                        return _origFetch('/gw/' + ALIASES[key], opts);
                    }
                }
            }
        } catch (e) {  }
        return _origFetch.apply(this, arguments);
    };
})();

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.alert-close').forEach(button => {
        button.addEventListener('click', function() {
            const alert = this.parentElement;
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100px)';
            setTimeout(() => alert.remove(), 400);
        });
    });

    window.closeModalFade = function(m) {
        if (!m || !m.classList.contains('active')) return;
        m.classList.add('closing');
        m.classList.remove('active');

        setTimeout(() => m.classList.remove('closing'), 320);
    };

    function _nsModal(m) { return m && m.closest && m.closest('#ns-root'); }

    document.addEventListener('click', function(e) {

        const btn = e.target.closest('.modal .close');
        if (btn) {
            const m = btn.closest('.modal');
            if (m && !btn.hasAttribute('data-modal') && !_nsModal(m)) {
                window.closeModalFade(m);
            }
            return;
        }

        if (e.target.classList && e.target.classList.contains('modal') && !_nsModal(e.target)) {
            window.closeModalFade(e.target);
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.active').forEach(m => {
                if (_nsModal(m)) return;
                window.closeModalFade(m);
            });
        }
    });

    document.querySelectorAll('.alert').forEach(alert => {
        setTimeout(() => {
            if (alert.parentElement) {
                alert.style.opacity = '0';
                alert.style.transform = 'translateX(100px)';
                setTimeout(() => alert.remove(), 400);
            }
        }, 5000);
    });

    const tableRows = document.querySelectorAll('.machine-table tbody tr');
    tableRows.forEach((row, i) => {
        row.style.animationDelay = (i * 0.07) + 's';
    });

    document.querySelectorAll('.machine-row').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function() {
            window.location.href = this.getAttribute('data-href');
        });
    });
});

const _TOAST_ICONS = {
    success: 'fa-circle-check',
    danger: 'fa-circle-xmark',
    error: 'fa-circle-xmark',
    warning: 'fa-triangle-exclamation',
    info: 'fa-circle-info',
};

function showToast(message, category = 'success') {
    const container = document.querySelector('.toast-container');
    if (!container) return;
    const cat = ['success', 'danger', 'error', 'warning', 'info'].includes(category)
        ? category : 'info';

    const alert = document.createElement('div');
    alert.className = `alert alert-${cat} toast-show`;
    alert.innerHTML = `
        <i class="fas ${_TOAST_ICONS[cat] || 'fa-circle-info'} alert-icon"></i>
        <span>${message}</span>
        <button class="alert-close">
            <i class="fas fa-times"></i>
        </button>
    `;

    container.appendChild(alert);

    alert.querySelector('.alert-close').addEventListener('click', () => {
        alert.style.opacity = '0';
        alert.style.transform = 'translateX(100px)';
        setTimeout(() => alert.remove(), 400);
    });

    setTimeout(() => {
        if (alert.parentElement) {
            alert.style.opacity = '0';
            alert.style.transform = 'translateX(100px)';
            setTimeout(() => alert.remove(), 400);
        }
    }, 5000);
}

(function sessionGuard() {
    if (location.pathname.indexOf('/login') === 0) return;
    const _origFetch = window.fetch ? window.fetch.bind(window) : null;
    if (!_origFetch) return;

    function _expired() {
        if (window._sessionExpiredDone) return;
        window._sessionExpiredDone = true;
        window.location.href = '/login?expired=1';
    }

    window.fetch = async function (...args) {
        const r = await _origFetch(...args);
        try {
            let path = '';
            try { path = new URL(r.url, location.origin).pathname; } catch (e) {  }
            const ct = r.headers.get('content-type') || '';

            if (path === '/login' && !ct.includes('application/json')) {
                _expired();
                return r;
            }

            if (r.status === 401 && ct.includes('application/json')) {
                const j = await r.clone().json().catch(() => null);
                if (j && j.session_expired) _expired();
            }
        } catch (e) {  }
        return r;
    };
})();

(function splashScreen() {
    const el = document.getElementById('splash-screen');
    if (!el) return;

    const MIN_VISIBLE_MS = 350;
    const MAX_WAIT_MS    = 7000;
    const startedAt      = performance.now();

    let dataReady = !window.SPLASH_WAIT_DATA;
    let winLoaded = document.readyState === 'complete';
    let hidden    = false;

    function tryHide() {
        if (hidden || !winLoaded || !dataReady) return;

        const wait = Math.max(0, MIN_VISIBLE_MS - (performance.now() - startedAt));
        setTimeout(hideNow, wait);
    }

    function hideNow() {
        if (hidden) return;
        hidden = true;
        el.classList.add('splash-hide');
        document.body.classList.add('app-ready');

        setTimeout(() => el.remove(), 500);

        window.dispatchEvent(new CustomEvent('app:splash-hidden'));
    }

    window.addEventListener('app:data-ready', () => { dataReady = true; tryHide(); });
    window.addEventListener('load',           () => { winLoaded = true; tryHide(); });

    setTimeout(() => { winLoaded = true; dataReady = true; tryHide(); }, MAX_WAIT_MS);
})();

(function aiHub() {
    function ready(fn) {
        if (document.readyState !== 'loading') fn();
        else document.addEventListener('DOMContentLoaded', fn);
    }

    ready(function () {
        var fab = document.getElementById('ai-fab');
        var panel = document.getElementById('ai-chat');
        if (!fab || !panel) return;

        var T = window.AI_T || {};
        var msgs = panel.querySelector('#ai-messages');
        var form = panel.querySelector('#ai-form');
        var input = panel.querySelector('#ai-input');
        var sendBtn = panel.querySelector('#ai-send');
        var notifList = panel.querySelector('#ai-notif-list');
        var fabBadge = document.getElementById('ai-fab-badge');
        var tabBadge = document.getElementById('ai-tab-notif-badge');
        var pending = false;

        var chatLoaded = false;
        var loadingHistory = false;
        var greeted = false;
        var unread = 0;
        var activeTab = 'notif';

        function t(k) { return T[k] || k; }

        function fmtParams(tmpl, params) {
            try { return tmpl.replace(/\{(\w+)\}/g, function (_, k) {
                return (params && params[k] != null) ? params[k] : '{' + k + '}';
            }); } catch (e) { return tmpl; }
        }

        function relTime(iso) {
            try {
                var d = new Date(iso);
                var s = Math.floor((Date.now() - d.getTime()) / 1000);
                if (s < 60) return t('now');
                if (s < 3600) return Math.floor(s / 60) + ' min';
                if (s < 86400) return Math.floor(s / 3600) + ' h';
                return Math.floor(s / 86400) + ' d';
            } catch (e) { return ''; }
        }

        function setBadge(n) {
            unread = n || 0;
            if (fabBadge) {
                fabBadge.textContent = unread > 99 ? '99+' : String(unread);
                fabBadge.style.display = unread ? '' : 'none';
            }
            if (tabBadge) {
                tabBadge.textContent = unread > 99 ? '99+' : String(unread);
                tabBadge.style.display = unread ? '' : 'none';
            }
        }

        function pollUnread() {
            fetch('/notifications/api/unread')
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) { if (d && d.unread != null) setBadge(d.unread); })
                .catch(function () {  });
        }
        pollUnread();
        setInterval(pollUnread, 60000);

        function showTab(tab) {
            activeTab = tab;
            panel.querySelectorAll('.ai-tab').forEach(function (b) {
                b.classList.toggle('active', b.getAttribute('data-tab') === tab);
            });
            var nv = panel.querySelector('#ai-notif-view');
            var cv = panel.querySelector('#ai-chat-view');
            if (nv) nv.style.display = (tab === 'notif') ? '' : 'none';
            if (cv) cv.style.display = (tab === 'chat') ? '' : 'none';
            if (tab === 'notif') loadNotifications();

            if (tab === 'chat') loadChat();
        }
        panel.querySelectorAll('.ai-tab').forEach(function (b) {
            b.addEventListener('click', function () { showTab(b.getAttribute('data-tab')); });
        });

        var SEV_ICON = {
            info: 'fa-circle-info', warning: 'fa-triangle-exclamation',
            critical: 'fa-circle-exclamation'
        };

        function renderNotifs(items) {
            if (!notifList) return;
            notifList.textContent = '';
            if (!items.length) {
                var empty = document.createElement('div');
                empty.className = 'ai-notif-empty';
                empty.textContent = t('no_notifs');
                notifList.appendChild(empty);
                return;
            }
            items.forEach(function (it) {
                var row = document.createElement('div');
                row.className = 'ai-notif-item sev-' + (it.severity || 'info')
                    + (it.read ? ' read' : ' unread');
                var ic = document.createElement('span');
                ic.className = 'ai-notif-ico';
                ic.innerHTML = '<i class="fas ' + (SEV_ICON[it.severity] || SEV_ICON.info) + '"></i>';
                var body = document.createElement('div');
                body.className = 'ai-notif-body';
                var msg = document.createElement('div');
                msg.className = 'ai-notif-msg';
                msg.textContent = it.message || '';
                var meta = document.createElement('div');
                meta.className = 'ai-notif-meta';
                meta.textContent = (it.category_label || '') + ' · ' + relTime(it.created_at);
                body.appendChild(msg);
                body.appendChild(meta);
                row.appendChild(ic);
                row.appendChild(body);
                if (!it.read) {
                    var dot = document.createElement('span');
                    dot.className = 'ai-notif-dot';
                    row.appendChild(dot);
                    row.addEventListener('click', function () {
                        markRead(it.id, row);
                    });
                }

                if (t('admin') === true || t('admin') === 'true') {
                    var del = document.createElement('button');
                    del.type = 'button';
                    del.className = 'ai-notif-del';
                    del.title = t('del_item');
                    del.setAttribute('aria-label', t('del_item'));
                    del.innerHTML = '<i class="fas fa-trash-can"></i>';
                    del.addEventListener('click', function (ev) {
                        ev.stopPropagation();
                        deleteOne(it.id, row);
                    });
                    row.appendChild(del);
                }
                notifList.appendChild(row);
            });
        }

        function deleteOne(id, row) {
            fetch('/notifications/api/delete', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id })
            })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) {
                    if (!d) { showToast(t('del_fail'), 'danger'); return; }
                    if (d.unread != null) setBadge(d.unread);
                    if (row) row.remove();
                    showToast(t('del_ok'), 'success');
                    if (notifList && !notifList.children.length) loadNotifications();
                })
                .catch(function () { showToast(t('del_fail'), 'danger'); });
        }

        function loadNotifications() {
            if (!notifList) return;
            fetch('/notifications/api/list')
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) {
                    if (!d) return;
                    setBadge(d.unread || 0);
                    renderNotifs(d.items || []);
                })
                .catch(function () {
                    if (notifList) {
                        notifList.textContent = '';
                        var e = document.createElement('div');
                        e.className = 'ai-notif-empty';
                        e.textContent = t('fail');
                        notifList.appendChild(e);
                    }
                });
        }

        function markRead(id, row) {
            fetch('/notifications/api/read', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id })
            })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) {
                    if (d && d.unread != null) setBadge(d.unread);
                    if (row) row.classList.remove('unread');
                    var dot = row && row.querySelector('.ai-notif-dot');
                    if (dot) dot.remove();
                })
                .catch(function () {  });
        }

        var readAllBtn = panel.querySelector('#ai-notif-readall');
        if (readAllBtn) {
            readAllBtn.addEventListener('click', function () {
                fetch('/notifications/api/read_all', { method: 'POST' })
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (d) {
                        setBadge(0);
                        if (d) showToast(t('unread_all'), 'success');
                        loadNotifications();
                    })
                    .catch(function () {  });
            });
        }

        var clearReadBtn = panel.querySelector('#ai-notif-clearread');
        if (clearReadBtn) {
            clearReadBtn.addEventListener('click', function () {
                if (!window.confirm(t('del_read'))) return;
                fetch('/notifications/api/clear_read', { method: 'POST' })
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (d) {
                        if (!d) { showToast(t('del_fail'), 'danger'); return; }
                        setBadge(d.unread || 0);
                        showToast(t('del_read_ok'), 'success');
                        loadNotifications();
                    })
                    .catch(function () { showToast(t('del_fail'), 'danger'); });
            });
        }
        var checkBtn = panel.querySelector('#ai-notif-check');
        if (checkBtn) {
            checkBtn.addEventListener('click', function () {
                if (checkBtn.disabled) return;
                checkBtn.disabled = true;
                var ic = checkBtn.querySelector('i');
                if (ic) ic.className = 'fas fa-spinner fa-spin';
                fetch('/notifications/api/check', { method: 'POST' })
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (d) {
                        showToast(fmtParams(t('checked'), { n: (d && d.created) || 0 }), 'success');
                        loadNotifications();
                    })
                    .catch(function () {  })
                    .finally(function () {
                        checkBtn.disabled = false;
                        if (ic) ic.className = 'fas fa-rotate';
                    });
            });
        }

        function mdEscape(s) {
            return String(s).replace(/[&<>"']/g, function (c) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;',
                         '"': '&quot;', "'": '&#39;' }[c];
            });
        }

        function mdInline(s) {
            s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
            s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            s = s.replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s).,;:!?]|$)/g, '$1<em>$2</em>');
            s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
                '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
            return s;
        }

        function mdToHtml(src) {
            var lines = String(src).replace(/\r\n?/g, '\n').split('\n');
            var html = '', i = 0;
            var isTableSep = function (l) {
                return /^\s*\|?[\s:|-]+\|?\s*$/.test(l) && l.indexOf('-') !== -1;
            };
            var parseRow = function (l) {
                return l.trim().replace(/^\|/, '').replace(/\|$/, '')
                        .split('|').map(function (c) { return c.trim(); });
            };
            while (i < lines.length) {
                var line = lines[i];

                if (/^```/.test(line.trim())) {
                    i++;
                    var buf = [];
                    while (i < lines.length && !/^```/.test(lines[i].trim())) {
                        buf.push(lines[i]); i++;
                    }
                    i++;
                    html += '<pre class="md-code"><code>' +
                            mdEscape(buf.join('\n')) + '</code></pre>';
                    continue;
                }

                if (line.indexOf('|') !== -1 && line.trim() &&
                        (i + 1) < lines.length && isTableSep(lines[i + 1])) {
                    var head = parseRow(line);
                    i += 2;
                    var rows = [];
                    while (i < lines.length && lines[i].indexOf('|') !== -1 &&
                           lines[i].trim()) { rows.push(parseRow(lines[i])); i++; }
                    var tHtml = '<div class="md-table-wrap"><table><thead><tr>';
                    head.forEach(function (h) {
                        tHtml += '<th>' + mdInline(mdEscape(h)) + '</th>';
                    });
                    tHtml += '</tr></thead><tbody>';
                    rows.forEach(function (r) {
                        tHtml += '<tr>';
                        for (var c = 0; c < head.length; c++) {
                            tHtml += '<td>' + mdInline(mdEscape(r[c] || '')) + '</td>';
                        }
                        tHtml += '</tr>';
                    });
                    tHtml += '</tbody></table></div>';
                    html += tHtml;
                    continue;
                }

                var hm = line.match(/^(#{1,4})\s+(.*)$/);
                if (hm) {
                    var lvl = Math.max(Math.min(hm[1].length + 1, 5), 3);
                    html += '<h' + lvl + '>' + mdInline(mdEscape(hm[2])) + '</h' + lvl + '>';
                    i++;
                    continue;
                }

                if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { html += '<hr>'; i++; continue; }

                if (/^\s*[-*•]\s+/.test(line)) {
                    var ul = [];
                    while (i < lines.length && /^\s*[-*•]\s+/.test(lines[i])) {
                        ul.push(lines[i].replace(/^\s*[-*•]\s+/, '')); i++;
                    }
                    html += '<ul>' + ul.map(function (it) {
                        return '<li>' + mdInline(mdEscape(it)) + '</li>';
                    }).join('') + '</ul>';
                    continue;
                }

                if (/^\s*\d+[.)]\s+/.test(line)) {
                    var ol = [];
                    while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
                        ol.push(lines[i].replace(/^\s*\d+[.)]\s+/, '')); i++;
                    }
                    html += '<ol>' + ol.map(function (it) {
                        return '<li>' + mdInline(mdEscape(it)) + '</li>';
                    }).join('') + '</ol>';
                    continue;
                }

                if (/^\s*>\s?/.test(line)) {
                    var q = [];
                    while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
                        q.push(lines[i].replace(/^\s*>\s?/, '')); i++;
                    }
                    html += '<blockquote>' + mdInline(mdEscape(q.join(' '))) + '</blockquote>';
                    continue;
                }

                if (!line.trim()) { i++; continue; }

                var p = [];
                while (i < lines.length && lines[i].trim() &&
                       !/^\s*[-*•]\s+/.test(lines[i]) &&
                       !/^\s*\d+[.)]\s+/.test(lines[i]) &&
                       !/^#{1,4}\s+/.test(lines[i]) &&
                       !/^```/.test(lines[i].trim()) &&
                       !/^\s*>\s?/.test(lines[i]) &&

                       !/^\s*([-*_])\1{2,}\s*$/.test(lines[i]) &&
                       !(lines[i].indexOf('|') !== -1 &&
                         (i + 1) < lines.length && isTableSep(lines[i + 1]))) {
                    p.push(lines[i]); i++;
                }
                if (p.length) {
                    html += '<p>' + p.map(function (l) {
                        return mdInline(mdEscape(l));
                    }).join('<br>') + '</p>';
                } else {
                    i++;
                }
            }
            return html;
        }

        function bubble(cls, text, useMd) {
            var div = document.createElement('div');
            var c = (' ' + cls + ' ').replace(' user ', ' ai-user ')
                                     .replace(' assistant ', ' ai-assistant ');
            div.className = 'ai-msg ' + c.trim();

            if (useMd) {
                div.classList.add('md');
                div.innerHTML = mdToHtml(text);
            } else {
                div.textContent = text;
            }
            msgs.appendChild(div);
            msgs.scrollTop = msgs.scrollHeight;
            return div;
        }

        function greet() {
            greeted = true;
            fetch('/assistant/api/status')
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d && d.configured) {
                        bubble('assistant', t('hello'));
                    } else {
                        bubble('assistant error-bubble', t('no_key'));
                    }
                })
                .catch(function () {
                    bubble('assistant', t('hello'));
                });
        }

        function loadChat() {
            if (chatLoaded || loadingHistory) return;
            loadingHistory = true;
            fetch('/assistant/api/history')
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) {
                    chatLoaded = true;
                    loadingHistory = false;
                    var items = (d && Array.isArray(d.items)) ? d.items : [];
                    if (items.length) {
                        items.forEach(function (m) {
                            if (m.role === 'user') bubble('user', m.content);
                            else if (m.role === 'assistant')
                                bubble('assistant', m.content, true);
                        });
                        greeted = true;
                    } else {
                        greet();
                    }
                })
                .catch(function () {
                    chatLoaded = true;
                    loadingHistory = false;
                    greet();
                });
        }

        function typing(on) {
            var el = msgs.querySelector('.ai-typing');
            if (on && !el) {
                el = document.createElement('div');
                el.className = 'ai-msg ai-assistant ai-typing';
                el.innerHTML = '<span></span><span></span><span></span>';
                msgs.appendChild(el);
                msgs.scrollTop = msgs.scrollHeight;
            } else if (!on && el) {
                el.remove();
            }
        }

        function setBusy(on) {
            pending = on;
            if (sendBtn) sendBtn.disabled = on;
            if (input) input.disabled = on;
        }

        function send(text) {
            text = (text || '').trim();
            if (!text || pending) return;
            bubble('user', text);

            input.value = '';
            setBusy(true);
            typing(true);

            fetch('/assistant/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            })
                .then(function (r) {
                    return r.json().then(function (d) { return { code: r.status, d: d }; });
                })
                .then(function (res) {
                    typing(false);
                    var d = res.d || {};
                    if (res.code === 200 && d.reply) {

                        bubble('assistant', d.reply, true);
                    } else if (d.error === 'no_api_key') {
                        bubble('assistant error-bubble', t('no_key'));
                    } else if (d.error === 'invalid_api_key') {
                        bubble('assistant error-bubble', t('bad_key'));
                    } else if (d.error === 'rate_limited') {

                        var rb = bubble('assistant error-bubble', t('rate_limit'));
                        if (d.detail) {
                            var rs = document.createElement('div');
                            rs.className = 'ai-msg-detail';
                            rs.textContent = d.detail;
                            rb.appendChild(rs);
                        }
                    } else if (d.error === 'model_not_found') {
                        bubble('assistant error-bubble', t('bad_model'));
                    } else {

                        var msg = bubble('assistant error-bubble', t('fail'));
                        if (d.detail) {
                            var s = document.createElement('div');
                            s.className = 'ai-msg-detail';
                            s.textContent = d.detail;
                            msg.appendChild(s);
                        }
                    }
                    setBusy(false);
                    if (input) input.focus();
                })
                .catch(function () {
                    typing(false);
                    bubble('assistant error-bubble', t('fail'));
                    setBusy(false);
                });
        }

        if (form) {
            form.addEventListener('submit', function (e) {
                e.preventDefault();
                send(input ? input.value : '');
            });
        }

        panel.querySelectorAll('.ai-chip').forEach(function (chip) {
            chip.addEventListener('click', function () {
                send(chip.getAttribute('data-q') || chip.textContent);
            });
        });

        var clearChatBtn = panel.querySelector('#ai-history-clear');
        if (clearChatBtn) {
            clearChatBtn.addEventListener('click', function () {
                if (clearChatBtn.disabled) return;
                if (!window.confirm(t('new_chat_confirm'))) return;
                clearChatBtn.disabled = true;
                fetch('/assistant/api/history/clear', { method: 'POST' })
                    .then(function (r) { return r.ok ? r.json() : null; })
                    .then(function (d) {
                        msgs.textContent = '';
                        greeted = false;
                        chatLoaded = true;
                        greet();
                        if (d) showToast(t('new_chat_ok'), 'success');
                    })
                    .catch(function () {  })
                    .finally(function () { clearChatBtn.disabled = false; });
            });
        }

        function open() {
            panel.classList.add('ai-open');
            fab.classList.add('ai-hidden');
            showTab(unread > 0 ? 'notif' : 'chat');
            if (unread > 0) pollUnread();
        }

        function close() {
            panel.classList.remove('ai-open');
            fab.classList.remove('ai-hidden');
        }

        fab.addEventListener('click', open);
        var closeBtn = panel.querySelector('#ai-close');
        if (closeBtn) closeBtn.addEventListener('click', close);

        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && panel.classList.contains('ai-open')) close();
        });
    });
})();
