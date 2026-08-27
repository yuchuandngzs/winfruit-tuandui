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
            e.preventDefault();
            record('RIGHT_CLICK_BLOCKED');
            showToast('右键菜单已被防火墙拦截');
            return false;
        });

        /* ---- 开发者工具快捷键拦截（F12 / Ctrl+Shift+I/J/C / Ctrl+U） ---- */
        document.addEventListener('keydown', function(e) {
            const k = (e.key || '').toUpperCase();
            const isF12 = k === 'F12';
            const isCtrlShiftIJC = (e.ctrlKey || e.metaKey) && e.shiftKey && (k === 'I' || k === 'J' || k === 'C');
            const isViewSource = (e.ctrlKey || e.metaKey) && k === 'U';
            if (isF12 || isCtrlShiftIJC || isViewSource) {
                e.preventDefault();
                record('DEVTOOLS_SHORTCUT', k);
                showToast('开发者工具快捷键已被拦截');
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

        /* ---- 开发者工具开启检测（窗口尺寸差，仅提示不阻断） ---- */
        let devtoolsWarned = false;
        function checkDevtoolsOpen() {
            const gap = Math.max(window.outerWidth - window.innerWidth, window.outerHeight - window.innerHeight);
            if (gap > 220) {
                record('DEVTOOLS_OPEN_DETECTED');
                if (!devtoolsWarned) {
                    devtoolsWarned = true;
                    showToast('检测到开发者工具，站点处于受保护模式');
                }
            } else {
                devtoolsWarned = false;
            }
        }
        window.addEventListener('resize', throttle(checkDevtoolsOpen, 1000));
        checkDevtoolsOpen();

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
        const protectedSelectors = ['header', '.main-nav', '#home', '#notice', '#report', '#join'];
        const originalHTML = {};
        protectedSelectors.forEach(sel => {
            const el = document.querySelector(sel);
            if (el) originalHTML[sel] = el.innerHTML;
        });

        const fwObserver = new MutationObserver(function(mutations) {
            for (const m of mutations) {
                if (m.target && m.target.closest && m.target.closest('#userArea')) continue;
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
    const navLinks = document.querySelectorAll('.nav-link');
    const pages = document.querySelectorAll('.page');

    function switchPage(targetId) {

        pages.forEach(page => page.classList.remove('active'));
        document.getElementById(targetId).classList.add('active');
        navLinks.forEach(link => link.classList.remove('active'));
        document.querySelector('[data-target="' + targetId + '"]').classList.add('active');
        window.scrollTo({ top: 0, behavior: 'smooth' });
        location.hash = targetId;
        setTimeout(() => { initReveal(); }, 50);
    }

    navLinks.forEach(link => {
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

