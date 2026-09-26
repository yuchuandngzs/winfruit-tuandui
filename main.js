/* winfruit team site - main script (firewall v2.0 + auth + pages) */

    /* ============================================================
     * WinFruit 前端防火墙 v2.0
     * - 右键菜单 / 开发者工具快捷键 / 图片拖拽拦截
     * - 框架嵌套防护 + URL XSS 过滤
     * - DOM 防篡改：内容被改动时自动恢复（登录动态区域白名单）
     * - 拦截提示浮窗（节流，避免刷屏）
     * ============================================================ */
    (function() {
        'use strict';
        const FW = { version: '2.0', blockedCount: 0, log: [] };

        function record(type, detail) {
            FW.blockedCount++;
            FW.log.push({ type: type, time: new Date().toISOString(), detail: detail || '' });
            if (FW.log.length > 200) FW.log.shift();
        }

        /* ---- 拦截提示浮窗 ---- */
        const fwToast = document.createElement('div');
        fwToast.className = 'fw-toast';
        fwToast.setAttribute('role', 'alert');
        document.body.appendChild(fwToast);
        let toastTimer = null, toastLast = 0;
        function showToast(msg) {
            const now = Date.now();
            if (now - toastLast < 1200) return;
            toastLast = now;
            fwToast.textContent = '\u{1F6E1} ' + msg;
            fwToast.classList.add('show');
            clearTimeout(toastTimer);
            toastTimer = setTimeout(function() { fwToast.classList.remove('show'); }, 2200);
        }

        function throttle(fn, wait) {
            let last = 0;
            return function() {
                const now = Date.now();
                if (now - last >= wait) { last = now; fn(); }
            };
        }

        /* ---- 右键菜单拦截 ---- */
        document.addEventListener('contextmenu', function(e) {
            if (window.__wfAdmin) return true; // 管理员放行
            e.preventDefault();
            record('RIGHT_CLICK_BLOCKED');
            showToast('右键菜单已被防火墙拦截');
            return false;
        });

        /* ---- 开发人员密码弹窗（F12 / 快捷键触发，密码正确后放行） ---- */
        const DEV_PASSWORD = 'yuchuan0410';
        let devUnlocked = false;
        let devOverlay = null, devInput = null, devError = null;

        function buildDevModal() {
            const overlay = document.createElement('div');
            overlay.className = 'dev-modal-overlay';
            overlay.setAttribute('role', 'dialog');
            overlay.setAttribute('aria-modal', 'true');
            overlay.innerHTML =
                '<div class="dev-modal">' +
                    '<div class="dev-modal-icon">\u{1F510}</div>' +
                    '<h4>开发人员验证</h4>' +
                    '<p class="dev-modal-tip">请输入开发密码以访问开发者工具</p>' +
                    '<input type="password" class="dev-modal-input" placeholder="请输入密码" autocomplete="off">' +
                    '<p class="dev-modal-error">密码错误，请重试</p>' +
                    '<div class="dev-modal-btns">' +
                        '<button type="button" class="dev-btn cancel">取消</button>' +
                        '<button type="button" class="dev-btn confirm">确认</button>' +
                    '</div>' +
                '</div>';
            document.body.appendChild(overlay);
            devInput = overlay.querySelector('.dev-modal-input');
            devError = overlay.querySelector('.dev-modal-error');
            const confirmBtn = overlay.querySelector('.dev-btn.confirm');
            const cancelBtn = overlay.querySelector('.dev-btn.cancel');

            function submit() {
                if (devInput.value === DEV_PASSWORD) {
                    devUnlocked = true;
                    closeDevModal();
                    record('DEV_UNLOCKED');
                    showToast('开发人员模式已解锁');
                } else {
                    devError.classList.add('show');
                    overlay.querySelector('.dev-modal').classList.remove('shake');
                    void overlay.querySelector('.dev-modal').offsetWidth;
                    overlay.querySelector('.dev-modal').classList.add('shake');
                    devInput.select();
                }
            }
            confirmBtn.addEventListener('click', submit);
            devInput.addEventListener('keydown', function(e) {
                e.stopPropagation();
                const k = (e.key || '').toUpperCase();
                const isDevKey = k === 'F12' || ((e.ctrlKey || e.metaKey) && e.shiftKey && (k === 'I' || k === 'J' || k === 'C')) || ((e.ctrlKey || e.metaKey) && k === 'U');
                if (isDevKey) { if (!window.__wfAdmin) e.preventDefault(); return; }
                if (e.key === 'Enter') submit();
                if (e.key === 'Escape') closeDevModal();
            });
            cancelBtn.addEventListener('click', closeDevModal);
            overlay.addEventListener('click', function(e) {
                if (e.target === overlay) closeDevModal();
            });
            return overlay;
        }
        function openDevModal() {
            if (devUnlocked) return;
            if (!devOverlay) devOverlay = buildDevModal();
            devError.classList.remove('show');
            devInput.value = '';
            devOverlay.classList.add('show');
            setTimeout(function() { devInput.focus(); }, 60);
        }
        function closeDevModal() {
            if (devOverlay) devOverlay.classList.remove('show');
        }

        /* ---- 开发者工具快捷键（F12 / Ctrl+Shift+I/J/C / Ctrl+U） ---- */
        document.addEventListener('keydown', function(e) {
            const k = (e.key || '').toUpperCase();
            const isF12 = k === 'F12';
            const isCtrlShiftIJC = (e.ctrlKey || e.metaKey) && e.shiftKey && (k === 'I' || k === 'J' || k === 'C');
            const isViewSource = (e.ctrlKey || e.metaKey) && k === 'U';
            if (isF12 || isCtrlShiftIJC || isViewSource) {
                if (devUnlocked || window.__wfAdmin) return; // 已解锁或管理员，放行浏览器默认行为
                e.preventDefault();
                record('DEVTOOLS_SHORTCUT', k);
                openDevModal();
                return false;
            }
        });

        /* ---- 图片拖拽保护 ---- */
        document.addEventListener('dragstart', function(e) {
            if (e.target && e.target.tagName === 'IMG') {
                e.preventDefault();
                record('IMAGE_DRAG_BLOCKED');
                showToast('站点图片受防火墙保护');
                return false;
            }
        });

        /* ---- 开发者工具开启检测（窗口尺寸差，检测到就弹生气提示） ---- */
        let devtoolsAngry = false;
        function detectDevtools() {
            return Math.max(window.outerWidth - window.innerWidth, window.outerHeight - window.innerHeight) > 160;
        }
        function showAngryOverlay() {
            if (devtoolsAngry || devUnlocked || window.__wfAdmin) return;
            devtoolsAngry = true;
            record('DEVTOOLS_ANGRY');
            let ov = document.getElementById('angry-overlay');
            if (!ov) {
                ov = document.createElement('div');
                ov.id = 'angry-overlay';
                ov.innerHTML =
                    '<div class="angry-box">' +
                    '<div class="angry-face">😤</div>' +
                    '<div class="angry-title">网页生气了</div>' +
                    '<div class="angry-desc">检测到开发者工具被打开。<br>请把它关掉，然后刷新页面就能恢复。</div>' +
                    '<button type="button" class="angry-btn">我已关闭，刷新页面</button>' +
                    '</div>';
                ov.querySelector('.angry-btn').addEventListener('click', function () {
                    location.reload();
                });
                document.body.appendChild(ov);
                ov.classList.add('show');
            } else {
                ov.classList.add('show');
            }
        }
        function hideAngryOverlay() {
            const ov = document.getElementById('angry-overlay');
            if (ov) ov.classList.remove('show');
        }
        function watchDevtools() {
            if (detectDevtools()) {
                showAngryOverlay();
            } else {
                devtoolsAngry = false;
                hideAngryOverlay();
            }
        }
        window.addEventListener('resize', throttle(watchDevtools, 400));
        setInterval(watchDevtools, 1000);
        watchDevtools();

        /* ---- 框架嵌套防护 ---- */
        try {
            if (window.top !== window.self) {
                window.top.location = window.self.location;
            }
        } catch(e) {
            window.location.href = 'about:blank';
        }

        /* ---- URL XSS 过滤 ---- */
        function sanitizeURL() {
            const dangerousPatterns = [
                /<script[\s>]/i, /javascript:/i, /on\w+\s*=/i,
                /<iframe[\s>]/i, /<object[\s>]/i, /<embed[\s>]/i,
                /eval\s*\(/i, /document\.cookie/i
            ];
            const href = window.location.href;
            for (const pattern of dangerousPatterns) {
                if (pattern.test(href)) {
                    record('XSS_IN_URL', href);
                    window.location.href = window.location.pathname + window.location.hash;
                    return false;
                }
            }
            return true;
        }
        sanitizeURL();

        /* ---- DOM 防篡改（#userArea 为登录态动态渲染区域，白名单放行） ---- */
        const protectedSelectors = ['header', '.main-nav', '#home', '#team', '#notice', '#report', '#mirror', '#fruitapp', '#fruitai'];
        const originalHTML = {};
        protectedSelectors.forEach(sel => {
            const el = document.querySelector(sel);
            if (el) originalHTML[sel] = el.innerHTML;
        });

        const fwObserver = new MutationObserver(function(mutations) {
            for (const m of mutations) {
                if (m.target && m.target.closest && (m.target.closest('#userArea') || m.target.closest('#nav-avatar'))) continue;
                for (const sel of protectedSelectors) {
                    const el = document.querySelector(sel);
                    if (el && originalHTML[sel] !== undefined && el.innerHTML !== originalHTML[sel]) {
                        el.innerHTML = originalHTML[sel];
                        record('TAMPER_REVERTED', sel);
                        showToast('检测到内容篡改，已自动恢复');
                        break;
                    }
                }
            }
        });
        protectedSelectors.forEach(sel => {
            const el = document.querySelector(sel);
            if (el) fwObserver.observe(el, {childList: true, characterData: true, subtree: true});
        });

        /* ---- 控制台警示 ---- */
        const consoleStyle = 'color: #22d3ee; font-size: 16px; font-weight: bold;';
        const consoleWarnStyle = 'color: #f87171; font-size: 13px;';
        console.log('%c\u{1F6E1} WinFruit Firewall v' + FW.version, consoleStyle);
        console.log('%c本站受前端安全防护保护，请勿在此粘贴执行不明代码。', consoleWarnStyle);

        window.addEventListener('error', function(e) {
            FW.log.push({type: 'JS_ERROR', time: new Date().toISOString(), detail: e.message});
        });

        Object.defineProperty(window, 'WinFruitFW', {
            value: Object.freeze({
                version: FW.version,
                get blockedCount() { return FW.blockedCount; },
                get log() { return [...FW.log]; }
            }),
            writable: false,
            configurable: false
        });
    })();

    /* ============================================================
     * 页面切换逻辑
     * ============================================================ */
    const navLinks = document.querySelectorAll('.nav-link, .index-link');
    const pages = document.querySelectorAll('.page');

    function switchPage(targetId) {

        pages.forEach(page => page.classList.remove('active'));
        document.getElementById(targetId).classList.add('active');
        navLinks.forEach(link => link.classList.remove('active'));
        document.querySelector('[data-target="' + targetId + '"]').classList.add('active');
        window.scrollTo(0, 0);
        location.hash = targetId;
        setTimeout(() => { initReveal(); }, 50);
        markProd(targetId);
    }

    function markProd(id){
      const on = ['fruitapp','fruitai'].indexOf(id) > -1;
      const b = document.querySelector('.prod-btn');
      if(b) b.classList.toggle('active', on);
    }

    navLinks.forEach(link => {
        if (link.getAttribute('data-log')) return; // 日志入口不参与页面切换
        link.addEventListener('click', e => {
            e.preventDefault();
            const target = link.getAttribute('data-target');
            switchPage(target);
        });
    });

    window.addEventListener('load', () => {
        const hash = location.hash.replace('#', '');
        if (hash && document.getElementById(hash)) {
            switchPage(hash);
        } else {
            initReveal();
        }
    });

    /* ============================================================
     * 导航栏滚动阴影
     * ============================================================ */
    const mainNav = document.querySelector('.main-nav');
    function handleNavScroll() {
        if (window.scrollY > 10) {
            mainNav.classList.add('scrolled');
        } else {
            mainNav.classList.remove('scrolled');
        }
    }
    window.addEventListener('scroll', handleNavScroll, { passive: true });
    handleNavScroll();

    /* ============================================================
     * 滚动渐入动画（错峰入场）
     * ============================================================ */
    let revealObserver = null;
    function initReveal() {
        const reveals = document.querySelectorAll('.page.active .reveal');
        if (!revealObserver) {
            revealObserver = new IntersectionObserver((entries) => {
                let i = 0;
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const el = entry.target;
                        el.style.animationDelay = Math.min(i * 80, 400) + 'ms';
                        el.classList.add('visible');
                        el.addEventListener('animationend', function clear() {
                            el.style.animationDelay = '';
                            el.removeEventListener('animationend', clear);
                        });
                        revealObserver.unobserve(el);
                        i++;
                    }
                });
            }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });
        }
        reveals.forEach(el => {
            el.classList.remove('visible');
            revealObserver.observe(el);
        });
    }

    /* 产品中心：进入产品页 */
    document.addEventListener('click', function(e){
      const g = e.target.closest('[data-goto]');
      if(g){
        const t = g.getAttribute('data-goto');
        const links = document.querySelectorAll('.main-nav .nav-link');
        links.forEach(l => l.classList.toggle('active', l.getAttribute('data-target') === t));
        document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === t));
        window.scrollTo(0, 0);
        markProd(t);
        if(history.replaceState){ history.replaceState(null, '', '#' + t); }
        e.preventDefault();
      }
    });

    /* 产品中心：点击展开/收起下拉 */
    (function(){
      const toggle = document.getElementById('prodToggle');
      const nav = document.querySelector('.nav-prod');
      if(!toggle || !nav) return;
      toggle.addEventListener('click', function(e){
        e.preventDefault();
        nav.classList.toggle('open');
      });
      document.addEventListener('click', function(e){
        if(!nav.contains(e.target)) nav.classList.remove('open');
      });
      nav.querySelectorAll('.more-menu a').forEach(function(a){
        a.addEventListener('click', function(){ nav.classList.remove('open'); });
      });
    })();
    /* ============================================================
     * 账号系统（纯前端 localStorage 版，兼容 Cloudflare 静态托管）
     * 用户数据 / 登录态 / 日志全部存在浏览器本地
     * ============================================================ */
    (function() {
        'use strict';
        var USERS_KEY = 'wf_users';
        var SESSION_KEY = 'wf_session';
        var LOGS_KEY = 'wf_logs';
        var ADMIN_HASH = '9f8c9af5f76c0b9dfedd1b2338106a14dd93c17173cffd55a2aaae37eedb721d';
        var state = { role: null, username: null, bio: '' };

        function loadJSON(k, d) {
            try { return JSON.parse(localStorage.getItem(k)) || d; } catch (e) { return d; }
        }
        function saveJSON(k, v) { localStorage.setItem(k, JSON.stringify(v)); }

        function pushLog(type, msg) {
            var logs = loadJSON(LOGS_KEY, []);
            logs.push({ t: new Date().toLocaleString('zh-CN', { hour12: false }), type: type, msg: msg });
            if (logs.length > 300) logs.shift();
            saveJSON(LOGS_KEY, logs);
        }

        function initUsers() {
            var users = loadJSON(USERS_KEY, {});
            if (!users.admin) {
                users.admin = { role: 'admin', passhash: ADMIN_HASH, bio: '站长' };
                saveJSON(USERS_KEY, users);
            }
            return users;
        }

        function setAvatar() {
            var face = document.getElementById('avatar-face');
            var wrap = document.getElementById('nav-avatar');
            if (!face || !wrap) return;
            if (state.username) {
                face.textContent = state.username.charAt(0).toUpperCase();
                wrap.classList.add('logged');
                wrap.title = state.username;
            } else {
                face.textContent = '\u{1F464}';
                wrap.classList.remove('logged');
                wrap.title = '点击登录';
            }
            /* 导航日志入口：仅管理员可见 */
            var navLog = document.getElementById('nav-log');
            if (navLog) navLog.style.display = (state.username && state.role === 'admin') ? '' : 'none';
            /* 管理员：切换到独立后台界面 */
            showAdminPanel();
        }

        /* ========== 管理员独立后台 ========== */
        var activeAdLog = 'login.log';
        function escHtml(s) {
            return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        }
        function showAdminPanel() {
            var p = document.getElementById('admin-panel');
            if (!p) return;
            var admin = !!(state.username && state.role === 'admin');
            if (admin) {
                p.style.display = '';
                document.body.classList.add('admin-mode');
                refreshAdDash();
                loadAdUsers();
                loadAdLog(activeAdLog);
            } else {
                p.style.display = 'none';
                document.body.classList.remove('admin-mode');
            }
        }
        function refreshAdDash() {
            var nu = document.getElementById('ad-n-users');
            var nl = document.getElementById('ad-n-login');
            var na = document.getElementById('ad-n-access');
            fetch('/api/logs')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(j) {
                    var logs = j.logs || {};
                    nl.textContent = (logs['login.log'] || []).length;
                    na.textContent = (logs['access.log'] || []).length;
                })
                .catch(function() {
                    var logs = loadJSON(LOGS_KEY, []);
                    nl.textContent = logs.length;
                    na.textContent = '-';
                });
            fetch('/api/users')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(j) { nu.textContent = (j.users || []).length; })
                .catch(function() { nu.textContent = Object.keys(loadJSON(USERS_KEY, {})).length; });
        }
        function loadAdUsers() {
            var body = document.getElementById('ad-users-body');
            function render(list) {
                body.innerHTML = list.map(function(u) {
                    return '<tr><td>' + escHtml(u.username) + '</td>' +
                        '<td><span class="ad-badge ' + (u.role === 'admin' ? 'admin' : 'user') + '">' + (u.role === 'admin' ? '管理员' : '普通用户') + '</span></td>' +
                        '<td>' + escHtml(u.bio) + '</td></tr>';
                }).join('') || '<tr><td colspan="3">(暂无用户)</td></tr>';
            }
            fetch('/api/users')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(j) { render(j.users || []); })
                .catch(function() {
                    var users = loadJSON(USERS_KEY, {});
                    render(Object.keys(users).map(function(name) {
                        return { username: name, role: users[name].role || 'user', bio: users[name].bio || '' };
                    }));
                });
        }
        function loadAdLog(file) {
            var body = document.getElementById('ad-log-body');
            if (!body) return;
            fetch('/api/logs')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(j) {
                    var lines = (j.logs && j.logs[file]) || [];
                    body.textContent = lines.join('\n') || '(暂无记录)';
                })
                .catch(function() {
                    var logs = loadJSON(LOGS_KEY, []);
                    body.textContent = logs.map(function(l) { return l.t + '  [' + l.type + '] ' + l.msg; }).join('\n') || '(暂无记录)';
                });
        }
        function loadAdCode() {
            var body = document.getElementById('ad-code-body');
            if (!body) return;
            fetch('main.js').then(function(r) { return r.text(); }).then(function(t) {
                body.textContent = t;
            }).catch(function() { body.textContent = '加载代码失败'; });
        }
        /* 后台菜单切换 */
        document.querySelectorAll('.ad-menu').forEach(function(b) {
            b.addEventListener('click', function() {
                document.querySelectorAll('.ad-menu').forEach(function(x) { x.classList.remove('on'); });
                b.classList.add('on');
                document.querySelectorAll('.ad-page').forEach(function(p) { p.classList.toggle('on', p.id === 'ad-' + b.dataset.ad); });
                if (b.dataset.ad === 'dash') refreshAdDash();
                if (b.dataset.ad === 'users') loadAdUsers();
                if (b.dataset.ad === 'logs') loadAdLog(activeAdLog);
                if (b.dataset.ad === 'code') loadAdCode();
            });
        });
        document.querySelectorAll('.ad-logtab').forEach(function(t) {
            t.addEventListener('click', function() {
                document.querySelectorAll('.ad-logtab').forEach(function(x) { x.classList.remove('on'); });
                t.classList.add('on');
                activeAdLog = t.getAttribute('data-f');
                loadAdLog(activeAdLog);
            });
        });
        document.getElementById('ad-front').addEventListener('click', function() {
            document.getElementById('admin-panel').style.display = 'none';
            document.body.classList.remove('admin-mode');
        });
        document.getElementById('ad-logout').addEventListener('click', function() {
            pushLog('退出', state.username);
            fetch('/api/logout', { method: 'POST' }).catch(function() {});
            localStorage.removeItem(SESSION_KEY);
            location.reload();
        });

        /* 头像点击（事件委托） */
        document.addEventListener('click', function(e) {
            var t = e.target;
            if (!t || !t.closest || !t.closest('#nav-avatar')) return;
            if (!state.username) {
                location.href = 'login.html?from=' + encodeURIComponent(location.pathname + location.hash);
                return;
            }
            var ov = document.getElementById('pf-overlay');
            document.getElementById('pf-name').textContent = state.username;
            var roleEl = document.getElementById('pf-role');
            roleEl.textContent = state.role === 'admin' ? '管理员' : '普通用户';
            roleEl.className = 'pf-role' + (state.role === 'admin' ? ' admin' : '');
            document.getElementById('pf-bio').value = state.bio;
            document.getElementById('pf-tip').textContent = '';
            document.getElementById('pf-logs').style.display = state.role === 'admin' ? '' : 'none';
            ov.classList.add('show');
        });

        function closePf() { document.getElementById('pf-overlay').classList.remove('show'); }
        document.getElementById('pf-close').addEventListener('click', closePf);
        document.getElementById('pf-overlay').addEventListener('click', function(e) {
            if (e.target === this) closePf();
        });

        /* 保存简介（服务端优先，失败回退本地） */
        document.getElementById('pf-save').addEventListener('click', function() {
            var bio = document.getElementById('pf-bio').value.trim();
            var tip = document.getElementById('pf-tip');
            fetch('/api/profile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ bio: bio }) })
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function() {
                    state.bio = bio;
                    tip.style.color = '#16a34a';
                    tip.textContent = '简介已保存';
                })
                .catch(function() {
                    var users = initUsers();
                    if (!users[state.username]) { tip.textContent = '保存失败'; return; }
                    users[state.username].bio = bio;
                    saveJSON(USERS_KEY, users);
                    state.bio = bio;
                    pushLog('资料', state.username + ' 修改了简介');
                    tip.style.color = '#16a34a';
                    tip.textContent = '简介已保存';
                });
        });

        /* 退出登录（服务端优先，失败回退本地） */
        document.getElementById('pf-logout').addEventListener('click', function() {
            pushLog('退出', state.username);
            fetch('/api/logout', { method: 'POST' }).catch(function() {});
            localStorage.removeItem(SESSION_KEY);
            location.reload();
        });

        /* 管理员：代码日志面板（头像弹窗 + 导航日志入口共用） */
        document.getElementById('pf-logs').addEventListener('click', function() {
            document.getElementById('log-overlay').classList.add('show');
            loadLogTab('login.log');
        });
        var navLogLink = document.getElementById('nav-log');
        if (navLogLink) {
            navLogLink.addEventListener('click', function(e) {
                e.preventDefault();
                if (!window.__wfAdmin) return;
                /* 导航日志 → 进入独立管理后台 */
                document.getElementById('admin-panel').style.display = '';
                document.body.classList.add('admin-mode');
                refreshAdDash();
                loadAdUsers();
                loadAdLog(activeAdLog);
            });
        }
        document.getElementById('log-close').addEventListener('click', function() {
            document.getElementById('log-overlay').classList.remove('show');
        });
        document.getElementById('log-overlay').addEventListener('click', function(e) {
            if (e.target === this) this.classList.remove('show');
        });
        document.querySelectorAll('.log-tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.log-tab').forEach(function(t) { t.classList.remove('on'); });
                tab.classList.add('on');
                loadLogTab(tab.getAttribute('data-f'));
            });
        });

        function loadLogTab(file) {
            var body = document.getElementById('log-body');
            if (file === 'code') {
                fetch('main.js').then(function(r) { return r.text(); }).then(function(t) {
                    body.textContent = t;
                }).catch(function() { body.textContent = '加载代码失败'; });
                return;
            }
            /* 服务端日志文件优先（data/logs/*.log），失败回退本地 wf_logs */
            fetch('/api/logs')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(j) {
                    var lines = (j.logs && j.logs[file]) || [];
                    body.textContent = lines.join('\n') || '(暂无记录)';
                })
                .catch(function() {
                    var logs = loadJSON(LOGS_KEY, []);
                    var list = logs.map(function(l) { return l.t + '  [' + l.type + '] ' + l.msg; });
                    body.textContent = list.join('\n') || '(暂无记录)';
                });
        }

        /* 初始化登录态：服务端会话（cookie）优先，失败回退 localStorage */
        function initAuth() {
            var now = Date.now();
            var users = initUsers();
            function applyServer(me) {
                state.username = me.username;
                state.role = me.role || 'user';
                state.bio = me.bio || '';
                window.__wfUser = me.username;
                window.__wfAdmin = state.role === 'admin';
                setAvatar();
            }
            function fallback() {
                var s = loadJSON(SESSION_KEY, null);
                if (s && s.username && s.exp > now && users[s.username]) {
                    state.username = s.username;
                    state.role = users[s.username].role || 'user';
                    state.bio = users[s.username].bio || '';
                    window.__wfUser = s.username;
                    window.__wfAdmin = state.role === 'admin';
                    var lastVisit = loadJSON('wf_lastvisit', 0);
                    if (now - lastVisit > 600000) {
                        saveJSON('wf_lastvisit', now);
                        pushLog('访问', state.username);
                    }
                } else {
                    if (s) localStorage.removeItem(SESSION_KEY);
                    window.__wfUser = null;
                    window.__wfAdmin = false;
                }
                setAvatar();
            }
            fetch('/api/me')
                .then(function(r) { return r.ok ? r.json() : Promise.reject(); })
                .then(function(me) {
                    if (me && me.ok && me.username) { applyServer(me); return; }
                    throw new Error('no session');
                })
                .catch(function() { fallback(); });
        }
        initUsers();
        initAuth();
    })();
