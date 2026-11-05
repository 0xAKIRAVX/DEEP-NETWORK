/* ═══════════════════════════════════════════════════════════
   DEEP NETWORK — app logic (v__PANEL_VER__, VPS edition)
   First-run wizard · login · dashboard · users · subs · tools
   ═══════════════════════════════════════════════════════════ */
'use strict';
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const VER = '__PANEL_VER__';

  const S = { view: 'dashboard', state: null, stats: null, whoami: null, timers: [], fx: {}, subUser: null, ready: false };
  window.APP = S;

  // ─────────── tiny helpers ───────────
  async function api(path, body, method) {
    const opt = { method: method || (body ? 'POST' : 'GET'), headers: {} };
    if (body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch('/panel/api/' + path, opt);
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && path !== 'login' && path !== 'setup' && path !== 'whoami' && S.ready) { showLogin(); stopLoops(); throw new Error(j.error || 'unauthorized'); }
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  }
  let toastT;
  function toast(msg, cls) {
    const t = $('#toast'); t.textContent = msg; t.className = 'toast show ' + (cls || '');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2600);
  }
  function fmtGB(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return Math.max(0, Math.round(b)) + ' B';
  }
  function fmtRate(bps) {
    if (bps >= 1073741824) return (bps / 1073741824).toFixed(2) + ' GB/s';
    if (bps >= 1048576) return (bps / 1048576).toFixed(1) + ' MB/s';
    if (bps >= 1024) return (bps / 1024).toFixed(1) + ' KB/s';
    return Math.max(0, Math.round(bps)) + ' B/s';
  }
  function fmtUptime(s) {
    if (s < 60) return s + ' ثانیه';
    if (s < 3600) return Math.floor(s / 60) + ' دقیقه';
    if (s < 86400) return Math.floor(s / 3600) + ' ساعت';
    return Math.floor(s / 86400) + ' روز';
  }
  function fmtDur(s) {
    s = Math.max(0, Math.floor(s));
    if (s < 60) return s + ' ثانیه';
    if (s < 3600) return Math.floor(s / 60) + ' دقیقه';
    if (s < 86400) { const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60); return m ? h + ' ساعت و ' + m + ' دقیقه' : h + ' ساعت'; }
    const d = Math.floor(s / 86400), h2 = Math.floor((s % 86400) / 3600);
    return h2 ? d + ' روز و ' + h2 + ' ساعت' : d + ' روز';
  }
  function relTime(unix) {
    if (!unix) return '';
    const s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
    if (s < 60) return 'همین حالا';
    if (s < 3600) return Math.floor(s / 60) + ' دقیقه پیش';
    if (s < 86400) return Math.floor(s / 3600) + ' ساعت پیش';
    return Math.floor(s / 86400) + ' روز پیش';
  }
  async function copy(text, msg) {
    try { await navigator.clipboard.writeText(text); toast(msg || 'کپی شد ✓', 'ok'); }
    catch { toast('کپی ممکن نشد', 'err'); }
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  // ─────────── modal ───────────
  function modal(html) {
    const root = $('#modal-root');
    root.innerHTML = '<div class="modal-bg"><div class="modal">' + html + '</div></div>';
    const bg = $('.modal-bg', root);
    bg.addEventListener('click', e => { if (e.target === bg) root.innerHTML = ''; });
    $$('.modal h3 button', root).forEach(b => b.addEventListener('click', () => root.innerHTML = ''));
    return root;
  }
  function closeModal() { $('#modal-root').innerHTML = ''; }

  // ─────────── FX mount ───────────
  function mountLoginFX() {
    if (!S.fx.login) S.fx.login = FX.starField($('#fx-login'), { stars: 100, drift: 7 });
    if ($('#fx-setup') && !S.fx.setup) S.fx.setup = FX.starField($('#fx-setup'), { stars: 100, drift: 7 });
  }
  function mountDashFX() {
    if (!S.fx.dash) S.fx.dash = FX.starField($('#fx-dash'), { stars: 70, drift: 5 });
  }
  function mountDashCanvases() {
    if (!S.fx.wave) S.fx.wave = FX.wave('#wave');
    if (!S.fx.spark) S.fx.spark = FX.spark('#spark');
    if (!S.fx.globeInst) { S.fx.globeInst = FX.globe('#globe'); applyGlobeNodes(); }
  }
  function applyGlobeNodes() {
    const geo = S.stats && S.stats.geo;
    const user = S.whoami && S.whoami.lat != null ? S.whoami : null;
    if (FX.setGlobeNodes) FX.setGlobeNodes(geo, user);
  }

  // ═══════════════ BOOT: setup → login → dash ═══════════════
  async function boot() {
    mountLoginFX();
    // existing session? → straight to the dashboard
    try {
      const st = await api('state');
      S.state = st;
      if (st.settings && st.settings.setup_required) { S.ready = true; showSetup(); }
      else { S.ready = true; showDash(); }
      try { S.whoami = await api('whoami'); } catch { }
      return;
    } catch { /* no session — decide via the public mode endpoint */ }
    try {
      const m = await api('mode');
      S.ready = true;
      if (m.setup_required) showSetup(); else showLogin();
    } catch { S.ready = true; showLogin(); }
    try { S.whoami = await api('whoami'); } catch { }
  }

  function show(id) {
    ['setup', 'login', 'dash'].forEach(v => { const el = $('#' + v); if (el) el.hidden = (v !== id); });
    if (id === 'dash') { mountDashFX(); }
    else mountLoginFX();
  }
  function showSetup() { show('setup'); }
  function showLogin(user) {
    show('login');
    if (user) $('#f-user').value = user;
    setTimeout(() => { try { $('#f-pass').focus(); } catch { } }, 60);
  }
  function showDash() {
    show('dash');
    S.ready = true;
    startLoops();
    paintState();
    mountDashCanvases();
    $('#hd-avatar-img').src = '/panel/avatar.png?v=' + Math.floor(Date.now() / 60000);
  }

  // ═══════════════ SETUP WIZARD ═══════════════
  const wiz = { photo: null, first: '', last: '' };

  function suStep(n) {
    $('#su-form-1').hidden = n !== 1;
    $('#su-form-2').hidden = n !== 2;
    $('#su-done').hidden = n !== 3;
    $('#su-d1').className = n >= 1 ? 'on' : '';
    $('#su-d2').className = n >= 2 ? 'on' : '';
    $('#su-d3').className = n >= 3 ? 'on' : '';
    $('#su-sub').textContent = n === 1 ? 'به شبکه‌ات خوش آمدی' : n === 2 ? 'یک قدم مانده' : 'آماده‌ای';
    mountLoginFX();
  }

  function initSetup() {
    suStep(1);

    // photo picker — canvas-downscale to 256, base64 PNG
    $('#su-file').addEventListener('change', ev => {
      const f = ev.target.files && ev.target.files[0];
      if (!f) return;
      const img = new Image();
      img.onload = () => {
        const side = Math.min(img.width, img.height);
        const cv = document.createElement('canvas'); cv.width = 256; cv.height = 256;
        const cx = cv.getContext('2d');
        cx.drawImage(img, (img.width - side) / 2, (img.height - side) / 2, side, side, 0, 0, 256, 256);
        const b64 = cv.toDataURL('image/png');
        wiz.photo = b64;
        $('#su-photo-img').src = b64;
      };
      img.onerror = () => toast('تصویر قابل خواندن نبود', 'err');
      img.src = URL.createObjectURL(f);
    });

    $('#su-form-1').addEventListener('submit', async ev => {
      ev.preventDefault();
      const first = $('#su-first').value.trim(), last = $('#su-last').value.trim();
      const err = $('#su-error-1');
      if (!first || !last) { err.textContent = 'نام و نام خانوادگی را کامل وارد کن'; err.hidden = false; return; }
      err.hidden = true;
      wiz.first = first; wiz.last = last;
      suStep(2);
      setTimeout(() => { try { $('#su-user').focus(); } catch { } }, 60);
    });

    $('#su-back-2').addEventListener('click', () => suStep(1));

    const suEye = $('#su-eye'), suPass = $('#su-pass');
    suEye.addEventListener('click', () => {
      suPass.type = suPass.type === 'password' ? 'text' : 'password';
    });

    suPass.addEventListener('input', () => {
      const v = suPass.value;
      let score = 0;
      if (v.length >= 8) score++;
      if (v.length >= 12) score++;
      if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
      if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) score++;
      const m = $('#su-meter-bar').parentElement;
      m.className = 'su-meter' + (v ? ' w' + Math.max(1, score) : '');
    });

    $('#su-form-2').addEventListener('submit', async ev => {
      ev.preventDefault();
      const err = $('#su-error-2');
      const user = $('#su-user').value.trim(), pass = suPass.value, pass2 = $('#su-pass2').value;
      if (!/^[a-zA-Z0-9_.-]{2,32}$/.test(user)) { err.textContent = 'نام کاربری باید ۲ تا ۳۲ حرف انگلیسی، عدد، نقطه یا خط تیره باشد'; err.hidden = false; return; }
      if (pass.length < 8) { err.textContent = 'رمز عبور باید حداقل ۸ کاراکتر باشد'; err.hidden = false; return; }
      if (pass !== pass2) { err.textContent = 'رمز و تکرار آن یکسان نیستند'; err.hidden = false; return; }
      err.hidden = true;
      try {
        await api('setup', { first: wiz.first, last: wiz.last, user, pass, avatar: wiz.photo || '' });
        $('#su-done-name').textContent = wiz.first + ' ' + wiz.last + ' — خوش آمدی';
        suStep(3);
      } catch (e) { err.textContent = e.message; err.hidden = false; }
    });

    $('#su-enter').addEventListener('click', () => {
      const u = $('#su-user').value.trim();
      showLogin(u);
    });
  }

  // ═══════════════ LOGIN ═══════════════
  function initLogin() {
    const eye = $('#eye'), pass = $('#f-pass');
    eye.addEventListener('click', () => { pass.type = pass.type === 'password' ? 'text' : 'password'; });
    $('#login-form').addEventListener('submit', async ev => {
      ev.preventDefault();
      const err = $('#login-error');
      err.hidden = true;
      const btn = $('.lc-submit', $('#login'));
      btn.disabled = true;
      try {
        const user = $('#f-user').value.trim();
        await api('login', { user, pass: pass.value });
        if ($('#f-remember').checked) { try { localStorage.setItem('dn-user', user); } catch { } }
        else { try { localStorage.removeItem('dn-user'); } catch { } }
        showDash();
      } catch (e) {
        err.textContent = e.message; err.hidden = false;
        if (/حسابی ساخته نشده/.test(e.message)) showSetup();
      } finally { btn.disabled = false; }
    });
    try { const u = localStorage.getItem('dn-user'); if (u) { $('#f-user').value = u; } } catch { }
  }

  // ═══════════════ DASH SHELL ═══════════════
  function initDash() {
    // sidebar nav
    $$('#sb-nav button').forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));
    $('#burger').addEventListener('click', () => {
      $('#sidebar').classList.toggle('open');
      $('#sb-backdrop').classList.toggle('show');
    });
    $('#sb-backdrop').addEventListener('click', () => {
      $('#sidebar').classList.remove('open');
      $('#sb-backdrop').classList.remove('show');
    });
    $('#search').addEventListener('input', () => {
      const q = $('#search').value.trim().toLowerCase();
      $$('#users-table .tr:not(.th)').forEach(r => { r.style.display = !q || r.textContent.toLowerCase().includes(q) ? '' : 'none'; });
    });
    document.addEventListener('keydown', e => {
      if (e.key === '/' && document.activeElement !== $('#search')) { e.preventDefault(); $('#search').focus(); }
    });
    $('#view-all').addEventListener('click', () => switchView('users'));
    $('#hd-avatar-wrap').addEventListener('click', () => avatarModal());
  }

  function switchView(v) {
    S.view = v;
    $$('#sb-nav button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
    const host = $('#view-host'), dv = $('#dash-views');
    if (v === 'dashboard') { host.hidden = true; host.innerHTML = ''; dv.hidden = false; mountDashCanvases(); }
    else {
      dv.hidden = true; host.hidden = false;
      host.innerHTML = views[v] ? views[v]() : '<p class="pad">در حال بارگذاری…</p>';
      if (hooks[v]) hooks[v]();
    }
    $('#sidebar').classList.remove('open');
    $('#sb-backdrop').classList.remove('show');
    window.scrollTo({ top: 0 });
  }

  // ═══════════════ LOOPS ═══════════════
  function stopLoops() { S.timers.forEach(clearInterval); S.timers = []; }
  function startLoops() {
    stopLoops();
    S.timers.push(setInterval(statLoop, 2000));
    S.timers.push(setInterval(stateLoop, 8000));
    S.timers.push(setInterval(pingLoop, 6000));
    statLoop(); stateLoop(); pingLoop();
  }

  let pingHist = [];
  async function pingLoop() {
    try {
      const t0 = performance.now();
      await api('ping');
      const ms = Math.round(performance.now() - t0);
      pingHist.push(ms); if (pingHist.length > 10) pingHist.shift();
      const med = pingHist.slice().sort((a, b) => a - b)[Math.floor(pingHist.length / 2)];
      FX.data.ping = med;
      const gp = $('#g-ping'); if (gp) gp.textContent = med + ' ms';
    } catch { }
    try { S.whoami = await api('whoami'); applyGlobeNodes(); } catch { }
  }

  async function statLoop() {
    try {
      const st = await api('stats');
      S.stats = st;
      paintStats(st);
      if (S.view === 'stats' || S.view === 'tools' || S.view === 'online') paintLiveView(st);
    } catch { }
  }

  async function stateLoop() {
    try {
      const st = await api('state');
      S.state = st;
      paintState();
      if (S.view !== 'dashboard') paintLiveView(st);
    } catch { }
  }

  // ═══════════════ PAINT: dashboard ═══════════════
  function paintStats(st) {
    if (S.view !== 'dashboard') return;
    const ts = st.hist && st.hist.t ? st.hist.t : [];
    FX.data.serverT = st.t || (ts.length ? ts[ts.length - 1] : 0);
    FX.data.hist = ts.map((t, i) => ({ t, rx: st.hist.rx[i], tx: st.hist.tx[i] }));
    FX.data.rx = st.rx; FX.data.tx = st.tx;
    FX.tweenNum($('#g-dl'), st.rx || 0, fmtRate);
    FX.tweenNum($('#g-ul'), st.tx || 0, fmtRate);
    FX.tweenNum($('#r-up'), st.tx || 0, fmtRate);
    FX.tweenNum($('#r-down'), st.rx || 0, fmtRate);
    $('#g-dl-tot').textContent = '(' + fmtGB(st.rx_total || 0) + ')';
    $('#g-ul-tot').textContent = '(' + fmtGB(st.tx_total || 0) + ')';

    // rings
    const setRing = (name, pct) => {
      const el = $('.ring[data-ring="' + name + '"]');
      if (!el) return;
      const fg = $('circle.fg', el), len = 2 * Math.PI * 34;
      fg.style.strokeDashoffset = String(len * (1 - Math.min(100, pct) / 100));
      FX.tweenNum($('b', el), pct, v => Math.round(v) + '%');
    };
    setRing('cpu', st.cpu || 0);
    setRing('ram', st.mem || 0);
    setRing('disk', (st.disk && st.disk.percent) || 0);
    $('#r-cpu-model').textContent = (st.cpu_model || 'CPU').split('(')[0].trim().slice(0, 28);
    $('#r-ram').textContent = fmtGB((st.mem_used || 0) * 1048576) + ' / ' + fmtGB((st.mem_total || 0) * 1048576);
    $('#r-disk').textContent = ((st.disk && st.disk.used) || 0).toFixed(1) + ' / ' + ((st.disk && st.disk.total) || 0).toFixed(1) + ' GB';

    // server info
    $('#si-os').textContent = st.os || '—';
    $('#si-uptime').textContent = fmtUptime(st.uptime || 0);
    const geo = st.geo;
    $('#si-loc').textContent = geo ? (geo.city + ', ' + geo.country) : '—';
    $('#si-addr').textContent = (S.state && S.state.settings && S.state.settings.server) || (geo && geo.ip) || '—';
    const ports = S.state && S.state.settings && S.state.settings.ports;
    $('#si-ports').textContent = ports ? ('Vision ' + ports.vision + ' · XHTTP ' + ports.xhttp + ' · gRPC ' + ports.grpc) : '—';
    applyGlobeNodes();
  }

  function paintState() {
    const st = S.state; if (!st) return;
    const set = st.settings || {};
    if (set.first) {
      $('#hd-user-name').textContent = set.user || 'admin';
      $('#sb-owner-name').textContent = set.first + ' ' + set.last;
    }
    const clients = st.clients || [];
    const active = clients.filter(c => c.status === 'active');
    $('#st-users').textContent = String(active.length);
    $('#sb-users-count').textContent = String(clients.length);
    let tot = 0; clients.forEach(c => tot += (c.up || 0) + (c.down || 0));
    $('#st-traffic').textContent = fmtGB(tot);
    // hero net badge
    const w = S.whoami;
    $('#hero-net').textContent = w && w.label ? w.label : 'DEEP NETWORK';
    // chip
    $('#chip-proto-label').textContent = 'Reality · Vision';
    // mini users table
    const tbl = $('#users-table');
    tbl.innerHTML = '<div class="tr th"><span>نام کاربری</span><span>وضعیت</span><span>حجم مصرف</span><span>عملیات</span></div>';
    const onl = clients.filter(c => c.online).slice(0, 5);
    if (!onl.length) {
      tbl.innerHTML += '<div class="tr"><span style="color:var(--tx3)">کاربری آنلاین نیست</span><span></span><span></span><span></span></div>';
    } else {
      onl.forEach(c => {
        tbl.innerHTML += '<div class="tr"><span>' + esc(c.name) + '</span>' +
          '<span><i class="dot"></i> آنلاین</span>' +
          '<span>' + fmtGB((c.up || 0) + (c.down || 0)) + '</span>' +
          '<span><button class="mini-btn" data-sub="' + esc(c.id) + '">اشتراک</button></span></div>';
      });
      $$('button[data-sub]', tbl).forEach(b => b.addEventListener('click', () => subModal(b.dataset.sub)));
    }
    const onlineCount = clients.filter(c => c.online).length;
    $('#sb-online-count').textContent = String(onlineCount);
  }

  // ═══════════════ VIEWS ═══════════════
  const views = {
    users: () => {
      const st = S.state || { clients: [] };
      let rows = '';
      (st.clients || []).forEach(c => {
        const stCls = c.status === 'active' ? 'ok' : (c.status === 'expired' ? 'err' : 'warn');
        const stTxt = c.status === 'active' ? (c.online ? 'آنلاین' : 'فعال') : (c.status === 'expired' ? 'منقضی' : 'پر شده');
        rows += '<div class="tr">' +
          '<span><b>' + esc(c.name) + '</b>' + (c.main ? ' <em class="tag">اصلی</em>' : '') + '</span>' +
          '<span><i class="dot ' + (c.online ? '' : 'off') + '"></i><span class="st ' + stCls + '">' + stTxt + '</span></span>' +
          '<span>↓ ' + fmtGB(c.down || 0) + ' · ↑ ' + fmtGB(c.up || 0) + '</span>' +
          '<span>' + (c.quota ? fmtGB(c.quota) : 'نامحدود') + (c.days_left ? ' · ' + c.days_left + ' روز' : '') + '</span>' +
          '<span class="ops">' +
          '<button class="mini-btn" data-act="sub" data-id="' + esc(c.id) + '">کانفیگ</button>' +
          '<button class="mini-btn" data-act="edit" data-id="' + esc(c.id) + '">ویرایش</button>' +
          (c.main ? '' : '<button class="mini-btn danger" data-act="del" data-id="' + esc(c.id) + '">حذف</button>') +
          '</span></div>';
      });
      return '<section class="vwrap"><h3 class="vtitle">کاربران</h3>' +
        '<div class="tbl wide"><div class="tr th"><span>نام</span><span>وضعیت</span><span>مصرف</span><span>حجم / انقضا</span><span>عملیات</span></div>' + rows + '</div></section>';
    },

    online: () => {
      return '<section class="vwrap"><h3 class="vtitle">کاربران آنلاین</h3>' +
        '<div id="online-live">در حال دریافت…</div>' +
        '<h3 class="vtitle" style="margin-top:22px">آخرین اتصال‌ها</h3>' +
        '<div id="online-off">در حال دریافت…</div></section>';
    },

    create: () => {
      return '<section class="vwrap narrow"><h3 class="vtitle">ساخت کاربر جدید</h3>' +
        '<label class="field"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5 20c1.2-3.6 3.8-5 7-5s5.8 1.4 7 5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="nu-name" type="text" placeholder="نام کاربر (مثلاً سارا)"></label>' +
        '<div class="duo-mini">' +
        '<label class="field"><svg viewBox="0 0 24 24"><path d="M4 7V5h13v2M9 5v2M6 12h9M12 9.5v5M17 12h3v8H4v-8h3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg><input id="nu-quota" type="number" min="0" placeholder="حجم (GB، ۰=نامحدود)"></label>' +
        '<label class="field"><svg viewBox="0 0 24 24"><rect x="4" y="5" width="16" height="16" rx="2.4" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8 3v4M16 3v4M4 10h16" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="nu-days" type="number" min="0" placeholder="انقضا (روز، ۰=نامحدود)"></label>' +
        '</div>' +
        '<label class="field"><svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="nu-note" type="text" placeholder="یادداشت (اختیاری)"></label>' +
        '<button class="lc-submit" id="nu-go" style="width:100%"><span>ساخت کاربر</span><i class="lc-arrow">←</i></button>' +
        '<p class="hint-line">شناسه (UUID) به‌صورت خودکار ساخته می‌شود و هر سه ترنسپورت برایش فعال است.</p></section>';
    },

    subs: () => {
      const st = S.state || { clients: [] };
      const clients = st.clients || [];
      if (!clients.length) return '<section class="vwrap"><p class="hint-line">کاربری وجود ندارد.</p></section>';
      let sel = S.subUser && clients.find(c => c.id === S.subUser) ? S.subUser : clients[0].id;
      const opts = clients.map(c => '<option value="' + esc(c.id) + '"' + (c.id === sel ? ' selected' : '') + '>' + esc(c.name) + (c.main ? ' (اصلی)' : '') + '</option>').join('');
      return '<section class="vwrap"><h3 class="vtitle">کانفیگ‌ها و اشتراک</h3>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5 20c1.2-3.6 3.8-5 7-5s5.8 1.4 7 5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><select id="sub-user">' + opts + '</select></label>' +
        '<div id="sub-box">در حال دریافت…</div>' +
        '<div class="guide"><b>افزودن به v2rayNG</b>' +
        '<ol><li>اپ v2rayNG را باز کن → تب <b>اشتراک‌ها</b> (Subscriptions) → آیکن ＋</li>' +
        '<li>لینک اشتراک بالا را در قسمت URL بگذار و ذخیره کن</li>' +
        '<li>منوی سه‌نقطه → <b>به‌روزرسانی اشتراک</b> — هر ۳ کانفیگ می‌آیند</li></ol>' +
        '<b>اگر همه کانفیگ‌ها -۱ شدند</b>' +
        '<ol><li>تنظیمات → آدرس تست اتصال → <code>http://www.gstatic.com/generate_204</code> (آدرس پیش‌فرض جواب نمی‌دهد)</li>' +
        '<li>ترتیب امتحان: Vision (سریع‌ترین) → XHTTP → gRPC</li></ol></div></section>';
    },

    stats: () => {
      return '<section class="vwrap"><h3 class="vtitle">آمار</h3><div id="stats-body">در حال دریافت…</div></section>';
    },

    tools: () => {
      return '<section class="vwrap narrow"><h3 class="vtitle">ابزارها</h3>' +
        '<div class="tool-card"><b>تست سلامت (Doctor)</b><p>اتصال واقعی از خود سرور از هر سه ترنسپورت — اگر سبز بود کانفیگ‌ها سالم‌اند.</p>' +
        '<button class="mini-btn" id="tl-doctor">اجرای تست</button><div id="tl-doctor-out" class="doc-out"></div></div>' +
        '<div class="tool-card"><b>ری‌استارت سرویس پروکسی</b><p>اگر کانفیگ‌ها وصل نمی‌شوند اول این را بزن.</p><button class="mini-btn" id="tl-restart">ری‌استارت</button></div>' +
        '<div class="tool-card"><b>پشتیبان‌گیری</b><p>دانلود فایل پشتیبان کاربران و تنظیمات.</p><a class="mini-btn" href="/panel/api/backup" download>دانلود پشتیبان</a></div>' +
        '<div class="tool-card"><b>راهنما (RAHNAMA)</b><p>راهنمای کامل فارسی برای کانفیگ‌ها.</p><a class="mini-btn" href="/panel/api/rahnama" download>دانلود راهنما</a></div>' +
        '<div class="tool-card"><b>لاگ سرور</b><p>آخرین رخدادهای سرویس.</p><button class="mini-btn" id="tl-log">نمایش لاگ</button><pre id="tl-log-out" class="log-out" hidden></pre></div>' +
        '</section>';
    },

    settings: () => {
      const set = (S.state && S.state.settings) || {};
      return '<section class="vwrap narrow"><h3 class="vtitle">تنظیمات</h3>' +
        '<div class="tool-card"><b>پروفایل</b>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5 20c1.2-3.6 3.8-5 7-5s5.8 1.4 7 5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="se-first" value="' + esc(set.first || '') + '" placeholder="نام"></label>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5 20c1.2-3.6 3.8-5 7-5s5.8 1.4 7 5M3 4h6M15 4h6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="se-last" value="' + esc(set.last || '') + '" placeholder="نام خانوادگی"></label>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5 20c1.2-3.6 3.8-5 7-5s5.8 1.4 7 5" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg><input id="se-user" value="' + esc(set.user || '') + '" placeholder="نام کاربری"></label>' +
        '<div class="duo-mini">' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="9.5" rx="2.2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg><input id="se-curpass" type="password" placeholder="رمز فعلی"></label>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><rect x="5" y="10.5" width="14" height="9.5" rx="2.2" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" fill="none" stroke="currentColor" stroke-width="1.5"/></svg><input id="se-newpass" type="password" placeholder="رمز جدید (خالی=بدون تغییر)"></label>' +
        '</div>' +
        '<button class="mini-btn" id="se-profile-save">ذخیره پروفایل</button></div>' +

        '<div class="tool-card"><b>سرور — جبهه‌های Reality (پیشرفته)</b>' +
        '<p>هر ترنسپورت با یک جبهه (SNI) متفاوت کار می‌کند. فقط اگر اپراتورت یکی را بسته عوض کن.</p>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><path d="M12 3l7 2.6v5.2c0 4.6-3 8.4-7 9.9-4-1.5-7-5.3-7-9.9V5.6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><input id="se-sni-vision" value="' + esc((set.snis && set.snis.vision) || '') + '" placeholder="SNI ترنسپورت Vision"></label>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><path d="M12 3l7 2.6v5.2c0 4.6-3 8.4-7 9.9-4-1.5-7-5.3-7-9.9V5.6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><input id="se-sni-xhttp" value="' + esc((set.snis && set.snis.xhttp) || '') + '" placeholder="SNI ترنسپورت XHTTP"></label>' +
        '<label class="field slim"><svg viewBox="0 0 24 24"><path d="M12 3l7 2.6v5.2c0 4.6-3 8.4-7 9.9-4-1.5-7-5.3-7-9.9V5.6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg><input id="se-sni-grpc" value="' + esc((set.snis && set.snis.grpc) || '') + '" placeholder="SNI ترنسپورت gRPC"></label>' +
        '<button class="mini-btn" id="se-server-save">ذخیره و ری‌استارت</button></div>' +

        '<div class="tool-card"><b>خروج</b><p>از حساب خود خارج شو.</p><button class="mini-btn danger" id="se-logout">خروج از حساب</button></div>' +
        '</section>';
    },

    support: () => {
      return '<section class="vwrap narrow"><h3 class="vtitle">راهنمای سریع</h3>' +
        '<div class="guide"><b>کانفیگ‌ها کار نمی‌کنند؟ (نمایش -۱)</b>' +
        '<ol><li>در v2rayNG: تنظیمات ← <b>آدرس تست اتصال</b> ← <code>http://www.gstatic.com/generate_204</code></li>' +
        '<li>کانفیگ <b>Vision</b> را امتحان کن (سریع‌ترین)، بعد XHTTP و gRPC</li>' +
        '<li>از ابزارها ← <b>تست سلامت</b> بزن — اگر همه سبز بودند مشکل از سرور نیست و اپراتور آن پورت/SNI را محدود کرده؛ جبهه SNI را در تنظیمات عوض کن</li></ol>' +
        '<b>بیشترین سرعت</b>' +
        '<ol><li>برای دانلود از <b>Vision</b> استفاده کن</li>' +
        '<li>Mux را در کلاینت خاموش نگه‌دار (پیش‌فرض خاموش است)</li></ol>' +
        '<b>رمز را فراموش کردی؟</b><p>در ترمینال سرور: <code>sudo /opt/deep-network/out --reset-pass</code> — صفحه ثبت‌نام دوباره می‌آید.</p></div>' +
        '<div class="tool-card"><b>وضعیت سرویس</b><div id="sup-health">در حال بررسی…</div></div>' +
        '</section>';
    },
  };

  // ─────────── view hooks (bind after render) ───────────
  const hooks = {
    users: () => {
      $$('#view-host button[data-act]').forEach(b => b.addEventListener('click', async () => {
        const id = b.dataset.id, act = b.dataset.act;
        if (act === 'sub') { subModal(id); return; }
        if (act === 'edit') { editModal(id); return; }
        if (act === 'del') {
          if (!confirm('این کاربر حذف شود؟')) return;
          try { await api('clients/delete', { id }); toast('حذف شد ✓', 'ok'); await stateLoop(); switchView('users'); } catch (e) { toast(e.message, 'err'); }
        }
      }));
    },
    online: () => onlinePaint(),
    create: () => {
      $('#nu-go').addEventListener('click', async () => {
        const name = $('#nu-name').value.trim();
        if (!name) { toast('نام را وارد کن', 'err'); return; }
        const quotaGB = parseInt($('#nu-quota').value || '0', 10);
        const days = parseInt($('#nu-days').value || '0', 10);
        try {
          await api('clients', { name, quota: quotaGB > 0 ? quotaGB * 1073741824 : 0, days, note: $('#nu-note').value.trim() });
          toast('کاربر ساخته شد ✓', 'ok');
          await stateLoop();
          switchView('users');
        } catch (e) { toast(e.message, 'err'); }
      });
    },
    subs: () => {
      $('#sub-user').addEventListener('change', e => { S.subUser = e.target.value; subPaint(); });
      S.subUser = $('#sub-user').value;
      subPaint();
    },
    stats: () => statsPaint(),
    tools: () => {
      $('#tl-doctor').addEventListener('click', async () => {
        const out = $('#tl-doctor-out');
        out.innerHTML = '<p>در حال اجرا… (تا ۳۰ ثانیه)</p>';
        try { await api('doctor', {}); } catch { }
        let n = 0;
        const t = setInterval(async () => {
          n++;
          try {
            const d = await api('doctor');
            if (d && d.results && d.at) {
              clearInterval(t);
              out.innerHTML = d.results.map(r =>
                '<div class="doc-row ' + (r.ok ? 'ok' : 'bad') + '"><b>' + esc(r.name) + '</b><span>' +
                (r.ok ? ('✓ سالم — ' + r.ms + 'ms') : ('✗ ' + esc(r.err || 'ناموفق'))) + '</span></div>').join('');
            }
          } catch { }
          if (n > 20) { clearInterval(t); out.innerHTML += '<p class="hint-line">زمان تمام شد — دوباره امتحان کن.</p>'; }
        }, 2500);
      });
      $('#tl-restart').addEventListener('click', async () => {
        try { await api('restart', {}); toast('ری‌استارت شد ✓', 'ok'); } catch (e) { toast(e.message, 'err'); }
      });
      $('#tl-log').addEventListener('click', async () => {
        const el = $('#tl-log-out');
        el.hidden = false;
        try { const l = await api('log'); el.textContent = (l.lines || []).join('\n').slice(-3000) || '— خالی —'; } catch (e) { el.textContent = e.message; }
      });
      doctorResultsPaint();
    },
    settings: () => {
      $('#se-profile-save').addEventListener('click', async () => {
        try {
          await api('profile', {
            first: $('#se-first').value.trim(), last: $('#se-last').value.trim(),
            user: $('#se-user').value.trim(),
            current_pass: $('#se-curpass').value, pass: $('#se-newpass').value,
          });
          toast('ذخیره شد ✓', 'ok');
          $('#se-curpass').value = ''; $('#se-newpass').value = '';
          await stateLoop();
        } catch (e) { toast(e.message, 'err'); }
      });
      $('#se-server-save').addEventListener('click', async () => {
        try {
          await api('settings', {
            sni_vision: $('#se-sni-vision').value.trim(), sni_xhttp: $('#se-sni-xhttp').value.trim(),
            sni_grpc: $('#se-sni-grpc').value.trim(),
          });
          toast('ذخیره شد — سرویس ری‌استارت می‌شود ✓', 'ok');
          await stateLoop();
        } catch (e) { toast(e.message, 'err'); }
      });
      $('#se-logout').addEventListener('click', async () => {
        try { await api('logout', {}); } catch { }
        stopLoops();
        showLogin();
      });
    },
    support: () => {
      api('health').then(h => {
        const el = $('#sup-health');
        if (!el) return;
        el.innerHTML = '<p>سرویس پروکسی: <b class="' + (h.xray ? 'ok-t' : 'err-t') + '">' + (h.xray ? 'فعال ✓' : 'غیرفعال ✗') + '</b></p>' +
          '<p class="hint-line">نسخه ' + esc(h.version || '') + ' · آپ‌تایم ' + fmtUptime(h.uptime || 0) + '</p>';
      }).catch(() => { });
    },
  };

  function paintLiveView() {
    if (S.view === 'stats') statsPaint();
    if (S.view === 'online') onlinePaint();
    if (S.view === 'subs') subPaint();
    if (S.view === 'tools') doctorResultsPaint();
  }

  // ─────────── subs view paint ───────────
  function subPaint() {
    const box = $('#sub-box'); if (!box) return;
    const st = S.state || {}; const id = S.subUser;
    const c = (st.clients || []).find(x => x.id === id);
    if (!c) { box.innerHTML = '<p class="hint-line">کاربر پیدا نشد.</p>'; return; }
    let linksHtml = '';
    (c.links || []).forEach(l => {
      linksHtml += '<div class="cfg-row">' +
        '<div class="cfg-name"><b>' + esc(l.net) + '</b><small>پورت ' + l.port + '</small></div>' +
        '<div class="cfg-url">' + esc(l.url) + '</div>' +
        '<div class="cfg-ops">' +
        '<button class="mini-btn" data-copy="' + esc(l.url) + '">کپی</button>' +
        '<button class="mini-btn" data-qr="' + esc(l.url) + '" data-qrname="' + esc(l.name) + '">QR</button>' +
        '</div></div>';
    });
    box.innerHTML =
      '<div class="sub-line"><span>لینک اشتراک (همه ۳ کانفیگ):</span></div>' +
      '<div class="linkbox"><span style="flex:1;direction:ltr;text-align:left">' + esc(c.sub_url) + '</span>' +
      '<button data-copy="' + esc(c.sub_url) + '" title="کپی"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>' +
      '<button data-qr="' + esc(c.sub_url) + '" title="QR"><svg viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M14 14h2v2h-2zm4 0h2v2h-2zm-4 4h2v2h-2zm4 0h2v2h-2z" fill="currentColor"/></svg></button></div>' +
      '<div class="sub-line" style="margin-top:10px"><span>کانفیگ تک‌تک:</span></div>' + linksHtml;
    $$('[data-copy]', box).forEach(b => b.addEventListener('click', () => copy(b.dataset.copy)));
    $$('[data-qr]', box).forEach(b => b.addEventListener('click', () => qrModal(b.dataset.qr, b.dataset.qrname || 'QR')));
  }

  // ─────────── modals ───────────
  function qrModal(data, name) {
    modal('<h3>' + esc(name || 'QR') + '<button>×</button></h3>' +
      '<div class="qr-box"><img src="/panel/api/qr?data=' + encodeURIComponent(data) + '" alt="QR"></div>' +
      '<p class="hint-line">با دوربین v2rayNG اسکن کن (تب اشتراک‌ها → آیکن اسکنر)</p>');
  }

  function subModal(id) {
    const c = (S.state && S.state.clients || []).find(x => x.id === id);
    if (!c) return;
    let links = '';
    (c.links || []).forEach(l => {
      links += '<div class="cfg-row"><div class="cfg-name"><b>' + esc(l.net) + '</b></div>' +
        '<div class="cfg-url">' + esc(l.url) + '</div>' +
        '<div class="cfg-ops"><button class="mini-btn" data-copy="' + esc(l.url) + '">کپی</button></div></div>';
    });
    const root = modal('<h3>کانفیگ‌های ' + esc(c.name) + '<button>×</button></h3>' +
      '<div class="linkbox"><span style="flex:1;direction:ltr;text-align:left;font-size:11px">' + esc(c.sub_url) + '</span>' +
      '<button id="m-copy" title="کپی"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button></div>' +
      '<div class="qr-box"><img src="/panel/api/qr?data=' + encodeURIComponent(c.sub_url) + '" alt="QR"></div>' + links);
    $('#m-copy', root).addEventListener('click', () => copy(c.sub_url));
    $$('[data-copy]', root).forEach(b => b.addEventListener('click', () => copy(b.dataset.copy)));
  }

  function editModal(id) {
    const c = (S.state && S.state.clients || []).find(x => x.id === id);
    if (!c) return;
    const root = modal('<h3>ویرایش ' + esc(c.name) + '<button>×</button></h3>' +
      '<label class="field slim"><input id="eu-name" value="' + esc(c.name) + '" placeholder="نام"></label>' +
      '<label class="field slim"><input id="eu-note" value="' + esc(c.note || '') + '" placeholder="یادداشت"></label>' +
      '<div class="duo-mini">' +
      '<label class="field slim"><input id="eu-quota" type="number" min="0" value="' + (c.quota ? Math.round(c.quota / 1073741824) : 0) + '" placeholder="حجم GB"></label>' +
      '<label class="field slim"><input id="eu-days" type="number" min="0" value="' + (c.days_left || 0) + '" placeholder="روز تا انقضا"></label></div>' +
      '<button class="mini-btn" id="eu-save">ذخیره</button> ' +
      (c.main ? '' : '<button class="mini-btn" id="eu-regen">تعویض UUID</button>'));
    $('#eu-save', root).addEventListener('click', async () => {
      try {
        await api('clients/edit', {
          id, name: $('#eu-name', root).value.trim(), note: $('#eu-note', root).value.trim(),
          quota: parseInt($('#eu-quota', root).value || '0', 10) * 1073741824,
          days: parseInt($('#eu-days', root).value || '0', 10),
        });
        toast('ذخیره شد ✓', 'ok'); closeModal(); await stateLoop(); switchView('users');
      } catch (e) { toast(e.message, 'err'); }
    });
    const reg = $('#eu-regen', root);
    if (reg) reg.addEventListener('click', async () => {
      if (!confirm('UUID عوض شود؟ لینک‌های قبلی این کاربر از کار می‌افتند.')) return;
      try { await api('clients/regen', { id }); toast('UUID جدید ساخته شد ✓', 'ok'); closeModal(); await stateLoop(); switchView('users'); } catch (e) { toast(e.message, 'err'); }
    });
  }

  function avatarModal() {
    const root = modal('<h3>تصویر پروفایل<button>×</button></h3>' +
      '<div class="av-edit"><img src="/panel/avatar.png?v=' + Date.now() + '" alt=""></div>' +
      '<label class="mini-btn file-btn">انتخاب عکس<input type="file" id="av-file" accept="image/png,image/jpeg,image/gif" hidden></label> ' +
      '<button class="mini-btn danger" id="av-del">حذف عکس</button>');
    $('#av-file', root).addEventListener('change', ev => {
      const f = ev.target.files && ev.target.files[0]; if (!f) return;
      const fd = new FormData(); fd.append('file', f);
      fetch('/panel/api/avatar', { method: 'POST', body: fd }).then(r => r.json()).then(j => {
        if (j.ok) { toast('عکس ذخیره شد ✓', 'ok'); closeModal(); $('#hd-avatar-img').src = '/panel/avatar.png?v=' + Date.now(); }
        else toast(j.error || 'خطا', 'err');
      }).catch(() => toast('خطا در ارسال', 'err'));
    });
    $('#av-del', root).addEventListener('click', async () => {
      try { await api('avatar/delete', {}); toast('حذف شد ✓', 'ok'); $('#hd-avatar-img').src = '/panel/avatar.png?v=' + Date.now(); closeModal(); } catch (e) { toast(e.message, 'err'); }
    });
  }

  // ─────────── online view ───────────
  async function onlinePaint() {
    const live = $('#online-live'); if (!live) return;
    try {
      const d = await api('online');
      let html = '<div class="tbl wide"><div class="tr th"><span>کاربر</span><span>مدت</span><span>سرعت</span><span>مصرف نشست</span></div>';
      if (!d.online || !d.online.length) html += '<div class="tr"><span style="color:var(--tx3)">کاربری آنلاین نیست</span><span></span><span></span><span></span></div>';
      else d.online.forEach(u => {
        html += '<div class="tr"><span><b>' + esc(u.name) + '</b> ' + (u.status === 'idle' ? '<em class="tag">آرام</em>' : '') + '</span>' +
          '<span>' + fmtDur(u.dur_s || 0) + '</span>' +
          '<span>↓ ' + fmtRate(u.down_bps || 0) + ' · ↑ ' + fmtRate(u.up_bps || 0) + '</span>' +
          '<span>↓ ' + fmtGB(u.down || 0) + ' · ↑ ' + fmtGB(u.up || 0) + '</span></div>';
      });
      html += '</div>';
      let off = '<div class="tbl wide"><div class="tr th"><span>کاربر</span><span>مدت اتصال</span><span>زمان قطع</span><span>مصرف</span></div>';
      if (!d.offline || !d.offline.length) off += '<div class="tr"><span style="color:var(--tx3)">رخدادی ثبت نشده</span><span></span><span></span><span></span></div>';
      else d.offline.slice(0, 15).forEach(u => {
        off += '<div class="tr"><span>' + esc(u.name) + '</span>' +
          '<span>' + fmtDur(u.dur_s || 0) + '</span>' +
          '<span>' + relTime(u.offline_at) + '</span>' +
          '<span>' + fmtGB((u.up || 0) + (u.down || 0)) + '</span></div>';
      });
      off += '</div>';
      live.innerHTML = html;
      const offEl = $('#online-off'); if (offEl) offEl.innerHTML = off;
    } catch { live.innerHTML = '<p class="hint-line">خطا در دریافت.</p>'; }
  }

  // ─────────── stats view ───────────
  function statsPaint() {
    const el = $('#stats-body'); if (!el) return;
    const st = S.stats, sst = S.state;
    if (!st) { el.innerHTML = '<p class="hint-line">در حال دریافت…</p>'; return; }
    const clients = (sst && sst.clients) || [];
    let totUp = 0, totDown = 0;
    clients.forEach(c => { totUp += c.up || 0; totDown += c.down || 0; });
    const sorted = clients.slice().sort((a, b) => ((b.up + b.down) || 0) - ((a.up + a.down) || 0)).slice(0, 10);
    let topRows = sorted.map(c => '<div class="tr"><span>' + esc(c.name) + '</span><span>↓ ' + fmtGB(c.down || 0) + '</span><span>↑ ' + fmtGB(c.up || 0) + '</span><span>' + fmtGB((c.up || 0) + (c.down || 0)) + '</span></div>').join('');
    el.innerHTML =
      '<div class="cards3">' +
      '<div class="stat"><div><b>' + fmtGB(totDown) + '</b></div><span>دانلود کل</span><small>مجموع ترافیک کاربران</small></div>' +
      '<div class="stat"><div><b>' + fmtGB(totUp) + '</b></div><span>آپلود کل</span><small>مجموع ترافیک کاربران</small></div>' +
      '<div class="stat"><div><b>' + (st.online_users || 0) + '</b></div><span>آنلاین‌ها</span><small>کاربر متصل در همین لحظه</small></div>' +
      '</div>' +
      '<div class="info-sec" style="margin-top:18px"><h3>سرور</h3><ul class="kv">' +
      '<li><span>سیستم عامل</span><b>' + esc(st.os || '—') + '</b></li>' +
      '<li><span>CPU</span><b>' + esc((st.cpu_model || '—').slice(0, 40)) + ' × ' + (st.cores || 1) + '</b></li>' +
      '<li><span>رم</span><b>' + fmtGB((st.mem_total || 0) * 1048576) + '</b></li>' +
      '<li><span>دیسک</span><b>' + ((st.disk && st.disk.total) || 0).toFixed(1) + ' GB</b></li>' +
      '<li><span>آپ‌تایم</span><b>' + fmtUptime(st.uptime || 0) + '</b></li>' +
      '<li><span>نسخه پنل</span><b>' + esc(st.version || '') + '</b></li>' +
      '</ul></div>' +
      '<div class="users-sec" style="margin-top:18px"><div class="sec-title"><b>بیشترین مصرف</b></div>' +
      '<div class="tbl wide"><div class="tr th"><span>کاربر</span><span>دانلود</span><span>آپلود</span><span>جمع</span></div>' + topRows + '</div></div>';
  }

  // ─────────── tools view: doctor results ───────────
  function doctorResultsPaint() {
    const out = $('#tl-doctor-out'); if (!out) return;
    const doc = S.state && S.state.settings && S.state.settings.doctor;
    if (!doc || !doc.length) { out.innerHTML = '<p class="hint-line">تستی اجرا نشده — دکمه بالا را بزن.</p>'; return; }
    out.innerHTML = doc.map(r =>
      '<div class="doc-row ' + (r.ok ? 'ok' : 'bad') + '"><b>' + esc(r.name) + '</b><span>' +
      (r.ok ? ('✓ سالم — ' + r.ms + 'ms') : ('✗ ' + esc(r.err || 'ناموفق'))) + '</span></div>').join('') +
      '<p class="hint-line">آخرین تست: ' + relTime(S.state.settings.doctor_at) + '</p>';
  }

  // ═══════════════ INIT ═══════════════
  document.addEventListener('DOMContentLoaded', () => {
    initSetup();
    initLogin();
    initDash();
    boot();
  });
})();
