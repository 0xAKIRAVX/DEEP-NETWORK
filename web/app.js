/* ═══════════════════════════════════════════════════════════
   DEEP NETWORK — app logic (v__PANEL_VER__)
   Real data only: stats polling, browser RTT ping, operator detect
   ═══════════════════════════════════════════════════════════ */
'use strict';
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const VER = '__PANEL_VER__';

  const S = { view: 'dashboard', state: null, stats: null, whoami: null, timers: [], fx: {} };
  window.APP = S;

  // ─────────── FinalMask & Cipher Suites — UI label maps ───────────
  const fpLabels = {
    chrome: 'اثر انگشت Chrome (پیش‌فرض — بهترین سازگاری)', firefox: 'اثر انگشت Firefox',
    safari: 'اثر انگشت Safari', ios: 'اثر انگشت iOS (آیفون)', android: 'اثر انگشت Android (موبایل)',
    edge: 'اثر انگشت Edge', random: 'تصادفی در هر اتصال', randomized: 'تصادفی پیوسته',
  };
  const alpnLabels = {
    '': 'خودکار (بهترین برای هر پروتکل)', 'http/1.1': 'HTTP/1.1 (سبک — WebSocket)',
    'h2': 'HTTP/2', 'h2,http/1.1': 'HTTP/2 + HTTP/1.1 (XHTTP)', 'http/1.1,h2': 'HTTP/1.1 + HTTP/2',
  };
  const cipherLabels = {
    TLS13: 'TLS 1.3 کامل — امن و سریع', TLS13_FAST: 'TLS 1.3 سریع — فقط AES-128',
    TLS12_AES: 'TLS 1.2 — AES-GCM', TLS12_CHACHA: 'TLS 1.2 — ChaCha20 (بهتر برای موبایل)',
  };

  // ─────────── tiny helpers ───────────
  async function api(path, body, method) {
    const opt = { method: method || (body ? 'POST' : 'GET'), headers: {} };
    if (body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    const r = await fetch('/panel/api/' + path, opt);
    const j = await r.json().catch(() => ({}));
    if (r.status === 401 && path !== 'login') { showLogin(); throw new Error(j.error || 'unauthorized'); }
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  }
  let toastT;
  function toast(msg, cls) {
    const t = $('#toast'); t.textContent = msg; t.className = 'toast show ' + (cls || '');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2600);
  }
  // v3.6: adaptive units — tiny values no longer render as "0.0 GB"/"0.0 MB/s"
  function fmtGB(b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + ' GB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
    return Math.max(0, Math.round(b)) + ' B';
  }
  function fmtRate(bps) { // bytes/second with adaptive unit
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
  // v3.10: online-monitor helpers — session duration / relative & clock time
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
  function clockTime(unix) {
    try { return new Date(unix * 1000).toLocaleTimeString('fa-IR-u-nu-latn', { hour: '2-digit', minute: '2-digit' }); }
    catch { return new Date(unix * 1000).toTimeString().slice(0, 5); }
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

  // ─────────── Telegram Mini App integration (v3.4) ───────────
  // The SDK is bundled locally (/panel/tg-webapp.js) — telegram.org is
  // filtered in Iran and a remote <script> would hang the whole panel inside
  // the Mini App. Outside Telegram the SDK is inert.
  function tgEnv() {
    const w = window.Telegram && window.Telegram.WebApp;
    if (!w || !w.initData) return null;
    return w;
  }
  function tgInit() {
    const tg = window.Telegram && window.Telegram.WebApp;
    if (!tg) return;
    try { tg.ready(); } catch { }
    try { tg.expand(); } catch { }
    try { if (tg.setHeaderColor) tg.setHeaderColor('#050505'); } catch { }
    try { if (tg.setBackgroundColor) tg.setBackgroundColor('#000000'); } catch { }
    // stable viewport height for iOS/Android webviews (100vh jumps around)
    try {
      if (tg.viewportStableHeight) {
        document.documentElement.style.setProperty('--tgvh', tg.viewportStableHeight + 'px');
      }
      if (tg.onEvent) tg.onEvent('viewportChanged', ev => {
        if (ev && ev.isStateStable && tg.viewportStableHeight)
          document.documentElement.style.setProperty('--tgvh', tg.viewportStableHeight + 'px');
      });
    } catch { }
  }

  // ─────────── login view ───────────
  function showLogin() {
    stopTimers();
    $('#dash').hidden = true;
    $('#login').hidden = false;
    setDashFX(false); // stop ALL dashboard canvases (not just the starfield)
    if (S.fx.dash) { try { S.fx.dash.stop(); } catch { } S.fx.dash = null; } // stop hidden canvas → real FPS
    if (!S.fx.login) S.fx.login = FX.starField($('#fx-login'), { stars: 100, drift: 7 });
  }
  function showDash() {
    $('#login').hidden = true;
    $('#dash').hidden = false;
    if (S.fx.login) { try { S.fx.login.stop(); } catch { } S.fx.login = null; }
    if (!S.fx.dash) S.fx.dash = FX.starField($('#fx-dash'), { stars: 70, drift: 5 });
    renderView('dashboard');
    startLoops();
    detectOperator();
  }

  // ─────────── profile picture upload ───────────
  let avatarV = 0;
  function bustAvatars() {
    avatarV = Date.now();
    const u = '/panel/avatar.png?v=' + avatarV;
    $$('img[data-avatar]').forEach(im => im.src = u);
    const hd = $('#hd-avatar-img'); if (hd) hd.src = u;
  }
  function pickAvatar() {
    const i = document.createElement('input');
    i.type = 'file'; i.accept = 'image/png,image/jpeg,image/gif,image/webp';
    i.addEventListener('change', async () => {
      const f = i.files && i.files[0];
      if (!f) return;
      if (f.size > 8 * 1024 * 1024) return toast('حجم تصویر بیش از ۸ مگابایت است', 'err');
      try {
        const fd = new FormData(); fd.append('file', f);
        const r = await fetch('/panel/api/avatar', { method: 'POST', body: fd });
        const j = await r.json().catch(() => ({}));
        if (r.status === 401) return toast('برای تغییر عکس پروفایل اول وارد شوید', 'err');
        if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
        bustAvatars();
        toast('تصویر پروفایل ذخیره شد ✓', 'ok');
      } catch (ex) { toast(ex.message, 'err'); }
    });
    i.click();
  }

  async function doLogin(e) {
    e.preventDefault();
    const err = $('#login-error'), btn = $('.lc-submit');
    err.hidden = true; btn.disabled = true;
    try {
      const user = $('#f-user').value.trim();
      await api('login', { user, pass: $('#f-pass').value });
      if ($('#f-remember').checked) localStorage.setItem('dn-user', user);
      else localStorage.removeItem('dn-user');
      const hd = $('#hd-user-name'); if (hd) hd.textContent = user || 'admin'; // was always static "admin"
      toast('خوش آمدید ✓', 'ok');
      showDash();
    } catch (ex) { err.textContent = ex.message; err.hidden = false; }
    btn.disabled = false;
  }

  function initLogin() {
    const saved = localStorage.getItem('dn-user');
    if (saved) $('#f-user').value = saved;
    $('#login-form').addEventListener('submit', doLogin);
    $('#eye').addEventListener('click', () => {
      const i = $('#f-pass'); i.type = i.type === 'password' ? 'text' : 'password';
    });
    $('#lc-cam').addEventListener('click', () => {
      // avatar upload needs a session; check quietly and open the picker if logged in
      fetch('/panel/api/ping').then(r => { if (r.ok) pickAvatar(); else toast('برای تغییر عکس پروفایل اول وارد شوید'); })
        .catch(() => toast('ارتباط با سرور برقرار نیست', 'err'));
    });
    $('#forgot').addEventListener('click', () => modal(`<h3>رمز عبور <button>✕</button></h3>
      <p style="font-size:12.5px;color:#bbb;line-height:2">
      اگر رمز را خودتان تنظیم نکرده‌اید، پنل آن را هنگام استقرار <b>خودکار ساخته</b> و در <b>لاگ‌های دیپلوی Lucity</b> چاپ کرده است.<br>
      متغیر محیطی <code style="font-family:var(--mono);direction:ltr;display:inline-block">ADMIN_PASSWORD</code> را در تنظیمات سرویس تنظیم کنید تا رمز دلخواه شما باشد. رمز جدید در پنل هم قابل تغییر است (تنظیمات ← مدیریت).</p>`));
    $('#btn-quick').addEventListener('click', async () => {
      try {
        const st = await api('state');
        const main = st.clients.find(c => c.main) || st.clients[0];
        if (!main) return toast('کاربری پیدا نشد', 'err');
        await copy(main.sub_url, 'لینک اشتراک سریع کپی شد — در کلاینت وارد (Import from clipboard) کنید ✓');
      } catch (ex) { toast(ex.message, 'err'); }
    });
    $('#btn-secure').addEventListener('click', async () => {
      try {
        const st = await api('state');
        const main = st.clients.find(c => c.main) || st.clients[0];
        // v3.6 FIX: was ?profile=fast — forced fragmentation OFF, the opposite
        // of "اتصال امن". No profile → serves the CURRENT saved tuning
        // (fragmentation/anti-DPI exactly as configured in Settings).
        location.href = '/panel/api/client/' + main.id;
      } catch (ex) { toast(ex.message, 'err'); }
    });
    $$('.lc-ico').forEach(b => b.addEventListener('click', async () => {
      const act = b.dataset.act;
      if (act === 'globe') {
        modal(`<h3>درباره DEEP NETWORK <button>✕</button></h3>
        <p style="font-size:12.5px;color:#bbb;line-height:2.1">نسخه <b>v${VER}</b> — بازنویسی کامل با <b>Go + Rust</b>.<br>
        هسته پروکسی: Xray-core · پنل: Go · اسکنر پینگ: Rust<br>
        SNI تصادفی ضد فیلتر، پروفایل‌های اپراتور ایران، فرگمنت TLS و کانفیگ بهینه برای هر اپراتور.</p>`);
      } else if (act === 'help') {
        modal(`<h3>راهنما <button>✕</button></h3>
        <p style="font-size:12.5px;color:#bbb;line-height:2">
        ۱) با نام کاربری و رمز وارد شوید (رمز در لاگ دیپلوی است اگر خودتان تنظیم نکرده‌اید).<br>
        ۲) از بخش «کاربران» لینک اشتراک هر کاربر را کپی یا QR آن را بگیرید.<br>
        ۳) در v2rayNG / Hiddify از طریق Import from clipboard اضافه کنید.<br>
        ۴) اگر اتصال برقرار نشد یا قطع و وصل شد: از «بهینه‌ساز و اسکنر» دکمه <b>«بهینه‌سازی خودکار برای شبکه من»</b> را بزنید — بهترین IP و تنظیمات اپراتور شما خودکار اعمال می‌شود، بعد اشتراک را در کلاینت به‌روزرسانی کنید.</p>`);
      } else if (act === 'settings') {
        toast('اول وارد شوید تا تنظیمات باز شود');
      }
    }));
  }

  // ─────────── view rendering ───────────
  // FIX: #view-host now lives INSIDE .ct (same margins as dashboard) and is
  // properly hidden + cleared when returning to the dashboard. Before, it was
  // appended at the end of #dash with no sidebar/header margin — view content
  // rendered behind the fixed header → "menu items never load".
  function setDashFX(on) {
    for (const k of ['wave', 'spark', 'globeInst']) {
      const fx = S.fx[k];
      if (!fx) continue;
      try { on ? (fx.resume ? fx.resume() : fx.start && fx.start()) : (fx.pause ? fx.pause() : fx.stop && fx.stop()); } catch { }
    }
  }
  function renderView(v) {
    S.view = v;
    $$('#sb-nav button').forEach(b => b.classList.toggle('on', b.dataset.view === v));
    const dashViews = $('#dash-views'), host = $('#view-host');
    if (v === 'dashboard') {
      history.replaceState(null, '', location.pathname); // location.hash='' scrolls & appends '#'
      dashViews.hidden = false;
      host.hidden = true; host.innerHTML = ''; // drop stale view DOM + listeners
      if (!S.fx.wave) S.fx.wave = FX.wave('#wave');
      if (!S.fx.spark) S.fx.spark = FX.spark('#spark');
      if (!S.fx.globeInst) { S.fx.globeInst = FX.globe('#globe'); applyGlobeNodes(); }
      setDashFX(true); // resume dashboard canvases
    } else {
      dashViews.hidden = true;
      setDashFX(false); // pause hidden dashboard canvases → zero cost
      host.hidden = false;
      // v3.10: leaving the online view stops its 2s poller (nothing burns hidden)
      if (v !== 'online') stopOnlineLoop();
      // FIX(v3.3): views that need S.state used to render ONCE with empty data
      // (state arrives a beat later on slow links) and never refresh → "menu
      // items never load". Now we mark the view stale and re-render it the
      // moment stateLoop delivers data.
      const needsState = v === 'users' || v === 'subs' || v === 'settings';
      S.viewStale = needsState && !S.state;
      try {
        host.innerHTML = views[v] ? views[v]() : '<p>به‌زودی</p>';
      } catch (err) {
        host.innerHTML = '<section class="info-sec" style="margin-top:20px"><h3>خطا</h3><p style="font-size:12px;color:#f8b4b4">در نمایش این بخش مشکلی پیش آمد: ' + esc(err.message) + '</p></section>';
      }
      if (viewsInit[v]) { try { viewsInit[v](); } catch (err) { console.error(err); } }
      window.scrollTo({ top: 0, behavior: 'instant' in window ? 'instant' : 'auto' });
    }
  }

  function applyGlobeNodes() {
    const geo = S.stats && S.stats.geo;
    const user = S.whoami && S.whoami.lat != null ? S.whoami : null;
    if (FX.setGlobeNodes) FX.setGlobeNodes(geo, user);
  }

  // ─────────── live stat loop (REAL data) ───────────
  let pingHist = [];
  async function statLoop() {
    try {
      const st = await api('stats');
      S.stats = st;
      paintStats(st);
    } catch { /* transient */ }
  }
  let pingEma = null; // v3.6: EMA display — the raw median jumps around every poll
  async function pingLoop() {
    const t0 = performance.now();
    try { await api('ping'); } catch { return; }
    const ms = Math.round(performance.now() - t0);
    pingHist.push(ms); if (pingHist.length > 8) pingHist.shift();
    const med = pingHist.slice().sort((a, b) => a - b)[Math.floor(pingHist.length / 2)];
    pingEma = pingEma == null ? med : pingEma * .7 + med * .3;
    const el = $('#g-ping'); if (el) el.textContent = Math.round(pingEma) + ' ms';
    const st = $('#g-status');
    if (st) st.textContent = pingEma < 130 ? 'عالی' : pingEma < 280 ? 'خوب' : 'متوسط';
    FX.data.ping = med;
  }

  function paintStats(st) {
    // v3.6: prefer the REAL per-sample timestamps from the server (sampler
    // jitter no longer shifts points); fall back to index-based estimates.
    const n = (st.hist && st.hist.rx) ? st.hist.rx.length : 0;
    const ts = (st.hist && st.hist.t && st.hist.t.length === n)
      ? st.hist.t : Array.from({ length: n }, (_, i) => (st.t || 0) - (n - 1 - i));
    FX.data.serverT = st.t || (n ? ts[n - 1] : 0);
    FX.data.hist = ts.map((t, i) => ({ t, rx: st.hist.rx[i], tx: st.hist.tx[i] }));
    FX.data.rx = st.rx; FX.data.tx = st.tx;
    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    // live numbers — eased via FX.tweenNum so they GLIDE at full frame rate
    FX.tweenNum($('#g-dl'), st.rx || 0, fmtRate);
    FX.tweenNum($('#g-ul'), st.tx || 0, fmtRate);
    FX.tweenNum($('#r-up'), st.tx || 0, fmtRate);
    FX.tweenNum($('#r-down'), st.rx || 0, fmtRate);
    set('#g-dl-tot', '(' + fmtGB(st.rx_total || 0) + ')');
    set('#g-ul-tot', '(' + fmtGB(st.tx_total || 0) + ')');
    set('#r-ram', st.mem_total >= 1024 ? (st.mem_used / 1024).toFixed(1) + ' / ' + (st.mem_total / 1024).toFixed(1) + ' GB' : st.mem_used + ' / ' + st.mem_total + ' MB');
    set('#r-disk', (st.disk.used || 0).toFixed(0) + ' / ' + (st.disk.total || 0).toFixed(1) + ' GB');
    set('#r-cpu-model', st.cpu_model || '—');
    set('#si-os', st.os || '—');
    set('#si-uptime', fmtUptime(st.uptime));
    set('#si-loc', st.geo ? (st.geo.city ? st.geo.city + '، ' : '') + st.geo.country : '—');
    set('#st-users', st.clients || 0);
    { const ps = S.state && S.state.settings.protocols || {}; let n = 0;
          for (const k of ['vless-ws','vless-xhttp','vless-hu','vmess-ws','trojan-ws']) if (ps[k]) n++;
          set('#st-proto', n); }
    set('#sb-users-count', st.clients || 0);
    // v3.10: live online users — sidebar badge, dashboard chip, stats view
    const onl = st.online_users || 0;
    set('#sv-onl-users', onl);
    { const sb = $('#sb-online-count'); if (sb) { sb.textContent = onl; sb.classList.toggle('none', !onl); } }
    { const dl = $('#st-users-delta'); if (dl) dl.textContent = onl ? onl + ' آنلاین' : ''; }
    ring('cpu', st.cpu || 0);
    ring('ram', st.mem || 0);
    ring('disk', st.disk.percent || 0);
    applyGlobeNodes();
    // v3.6: stats view updates IN PLACE (the old 5s full re-render flashed
    // and reset scroll position every refresh)
    const memStr = st.mem_total >= 1024 ? (st.mem_used / 1024).toFixed(1) + ' / ' + (st.mem_total / 1024).toFixed(1) + ' GB' : st.mem_used + ' / ' + st.mem_total + ' MB';
    set('#sv-cpu', (st.cpu || 0).toFixed(1) + '%');
    set('#sv-mem', memStr + ' (' + (Number(st.mem) || 0).toFixed(1) + '%)');
    set('#sv-disk', (st.disk.used || 0).toFixed(0) + ' / ' + (st.disk.total || 0).toFixed(1) + ' GB');
    set('#sv-dl', fmtGB(st.rx_total || 0));
    set('#sv-ul', fmtGB(st.tx_total || 0));
    set('#sv-t30', st.traffic30 && st.traffic30.bytes ? fmtGB(st.traffic30.bytes) : '—');
    set('#sv-online', st.online || 0);
    set('#sv-up', fmtUptime(st.uptime || 0));
  }
  function ring(name, pct) {
    const el = $('.ring[data-ring="' + name + '"]'); if (!el) return;
    FX.tweenNum($('b', el), pct, v => Math.round(v) + '%'); // number glides; arc has CSS transition
    const C = 2 * Math.PI * 34;
    const fg = $('circle.fg', el);
    fg.style.strokeDashoffset = C * (1 - Math.min(pct, 100) / 100);
  }

  async function stateLoop() {
    try {
      S.state = await api('state');
      paintState(S.state);
      // FIX(v3.3): if the current view was rendered before state existed,
      // re-render it now (menus never loaded otherwise on slow connections).
      if (S.viewStale && S.view !== 'dashboard') { S.viewStale = false; renderView(S.view); }
    } catch { }
  }
  function paintState(st) {
    // traffic total
    let up = 0, down = 0;
    for (const c of st.clients) { up += c.up || 0; down += c.down || 0; }
    const tEl = $('#st-traffic'); if (tEl) tEl.textContent = fmtGB(up + down);
    // v3.10: the old "+0" delta chip (delta-since-login) was meaningless —
    // the dashboard "کاربران" card now shows the LIVE online count instead.
    // users table (top 5) — online users are marked with a pulsing dot
    const tbl = $('#users-table');
    if (tbl) {
      $$('.tr:not(.th)', tbl).forEach(r => r.remove());
      for (const c of st.clients.slice(0, 5)) {
        const row = document.createElement('div');
        row.className = 'tr';
        const statusCell = c.online
          ? '<span class="u-status on"><i class="dot"></i>آنلاین · ' + fmtDur(c.online_dur || 0) + '</span>'
          : '<span class="u-status ' + (c.status !== 'active' ? c.status : 'off') + '"><i class="dot"></i>' + (c.status === 'active' ? 'آفلاین' : c.status === 'quota' ? 'پایان حجم' : 'منقضی') + (c.status === 'active' && c.last_seen ? ' <small style="color:#777">· ' + relTime(c.last_seen) + '</small>' : '') + '</span>';
        row.innerHTML = `<span class="u-name"><i class="u-ava">${esc(c.name[0] || '·').toUpperCase()}</i><b>${esc(c.name)}</b></span>
          ${statusCell}
          <span class="u-use">${fmtGB((c.up || 0) + (c.down || 0))}</span>
          <span class="u-act"></span>`;
        tbl.appendChild(row);
      }
    }
    // protocol chip
    const cp = $('#chip-proto-label');
    if (cp) {
      const protos = st.settings.protocols || {};
      const tcpReady = st.settings.tcp_ready;
      cp.textContent = tcpReady && protos['vless-reality'] ? 'Reality' : protos['vless-xhttp'] ? 'XHTTP' : protos['vless-ws'] ? 'VLESS-WS' : 'VLESS';
    }
  }

  // ─────────── views ───────────
  const views = {
    users() {
      const st = S.state || { clients: [] };
      return `<section class="users-sec" style="margin-top:20px">
      <div class="sec-title"><b>کاربران (${st.clients.length})</b>
        <div style="display:flex;gap:8px">
          <button class="mini-btn" id="add-user">+ کاربر جدید</button>
          <button class="mini-btn" id="export-backup">پشتیبان‌گیری</button>
        </div></div>
      <div class="tbl" id="all-users">
        <div class="tr th"><span>نام کاربری</span><span>وضعیت</span><span>حجم مصرف</span><span>عملیات</span></div>
        ${st.clients.map(c => `<div class="tr" data-id="${c.id}">
          <span class="u-name"><i class="u-ava">${esc(c.name[0] || '·').toUpperCase()}</i><b>${esc(c.name)}${c.main ? ' <small style="color:#777">(اصلی)</small>' : ''}</b></span>
          ${c.online ? `<span class="u-status on"><i class="dot"></i>آنلاین · ${fmtDur(c.online_dur || 0)}</span>`
            : c.status !== 'active' ? `<span class="u-status ${c.status}"><i class="dot"></i>${c.status === 'quota' ? 'پایان حجم' : 'منقضی'}</span>`
            : `<span class="u-status off"><i class="dot"></i>آفلاین${c.last_seen ? ' <small style="color:#777">· ' + relTime(c.last_seen) + '</small>' : ''}</span>`}
          <span class="u-use">${fmtGB((c.up || 0) + (c.down || 0))}</span>
          <span class="u-act">
            <button title="لینک اشتراک" data-act="sub"><svg viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1.2 1.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1.2-1.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg></button>
            <button title="ویرایش" data-act="edit"><svg viewBox="0 0 24 24"><path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg></button>
            <button title="حذف" data-act="del" ${c.main ? 'disabled style="opacity:.3"' : ''}><svg viewBox="0 0 24 24"><path d="M5 7h14M10 7V5h4v2m-7 0 1 13h8l1-13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
          </span></div>`).join('')}
      </div></section>`;
    },
    // v3.10: live online-users monitor — who is using the configs RIGHT NOW.
    online() {
      return `<section class="info-sec onl-sec" style="margin-top:20px">
      <h3>کاربران آنلاین <span class="onl-pill" id="onl-count">در حال دریافت…</span></h3>
      <p style="font-size:11.5px;color:#8d8d8d;margin:6px 0 12px;line-height:2">هر کاربری که در همین لحظه در حال استفاده از کانفیگ‌ها باشد، زنده (هر ۲ ثانیه) اینجا دیده می‌شود: مدت اتصال، سرعت لحظه‌ای و مصرف همین نشست. اگر ترافیک کاربری حدود ۹۰ ثانیه قطع بماند به فهرست «اخیراً آفلاین شده‌ها» با ساعت دقیق آفلاین‌شدن منتقل می‌شود. <b>وضعیت «بی‌تحرک»</b> یعنی اتصال هنوز باز است اما لحظه‌ای داده رد و بدل نشده.</p>
      <div class="tbl" id="onl-users">
        <div class="tr th"><span>کاربر</span><span>وضعیت</span><span>مدت اتصال</span><span>سرعت لحظه‌ای</span><span>مصرف این نشست</span></div>
      </div>
      <div class="onl-empty" id="onl-empty" hidden>در این لحظه هیچ کاربری آنلاین نیست</div>
      </section>
      <section class="info-sec onl-sec" style="margin-top:20px">
      <h3>اخیراً آفلاین شده‌ها</h3>
      <div class="tbl" id="off-users">
        <div class="tr th"><span>کاربر</span><span>مدت استفاده</span><span>زمان آفلاین شدن</span><span>مصرف نشست</span></div>
      </div>
      <div class="onl-empty" id="off-empty" hidden>هنوز سابقه‌ای ثبت نشده است</div>
      </section>`;
    },
    create() {
      return `<section class="info-sec" style="margin-top:20px;max-width:560px">
      <h3>ساخت کاربر جدید</h3>
      <label class="field" style="margin:10px 0"><input id="nu-name" placeholder="نام کاربر (مثلاً ali-iphone)"></label>
      <label class="field" style="margin:10px 0"><input id="nu-days" type="number" min="0" max="3650" placeholder="اعتبار (روز؛ خالی = نامحدود)"></label>
      <label class="field" style="margin:10px 0"><input id="nu-quota" type="number" min="0" placeholder="حجم (گیگابایت؛ خالی = نامحدود)"></label>
      <label class="field" style="margin:10px 0"><input id="nu-note" placeholder="یادداشت (اختیاری)"></label>
      <div class="btns"><button class="btn primary" id="nu-go">ایجاد کاربر</button></div>
      <p style="font-size:11px;color:#777;margin-top:10px">بعد از ایجاد، لینک اشتراک کاربر در بخش «کاربران» آماده است.</p>
      </section>`;
    },
    subs() {
      const st = S.state || { clients: [] };
      return `<section class="info-sec" style="margin-top:20px">
      <h3>اشتراک‌ها</h3>
      <p style="font-size:11.5px;color:#8d8d8d;margin:6px 0 14px;line-height:2"><b>استاندارد:</b> فهرست لینک‌ها (base64) — برای افزودن به عنوان Subscription در v2rayNG / Hiddify. <b>JSON بهینه:</b> پیکربندی کامل Xray با سریع‌ترین تنظیمات (Mux + KeepAlive + پروفایل اپراتور) — لینک را در مرورگر باز کنید، متن JSON را کپی کنید و در v2rayNG از منوی + ← «Import config from clipboard» وارد کنید.</p>
      ${st.clients.map(c => `<div style="padding:12px 0;border-bottom:1px dashed rgba(255,255,255,.08)">
        <div style="display:flex;align-items:center;gap:10px">
        <i class="u-ava">${esc(c.name[0] || '·').toUpperCase()}</i>
        <b style="font-size:13px;flex:1">${esc(c.name)}</b></div>
        <div style="margin-top:8px"><small style="font-size:10.5px;color:#8d8d8d">استاندارد (Subscription)</small>
        <div class="linkbox" style="margin-top:4px"><span style="flex:1">${esc(c.sub_url)}</span>
        <button data-copy="${esc(c.sub_url)}" title="کپی"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>
        <button data-qr="${esc(c.sub_url)}" title="QR"><svg viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M14 14h2v2h-2zm4 0h2v2h-2zm-4 4h2v2h-2zm4 0h2v2h-2z" fill="currentColor"/></svg></button></div></div>
        <div style="margin-top:8px"><small style="font-size:10.5px;color:#7fb98a">JSON بهینه — پرسرعت‌ترین (Mux فعال)</small>
        <div class="linkbox" style="margin-top:4px"><span style="flex:1">${esc(c.sub_url)}?fmt=xray</span>
        <button data-copy="${esc(c.sub_url)}?fmt=xray" title="کپی لینک JSON"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>
        <button data-qr="${esc(c.sub_url)}?fmt=xray" title="QR لینک JSON"><svg viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M14 14h2v2h-2zm4 0h2v2h-2zm-4 4h2v2h-2zm4 0h2v2h-2z" fill="currentColor"/></svg></button></div></div>
        </div>`).join('')}
      </section>`;
    },
    scanner() {
      const t = (S.state && S.state.settings.tuning) || {};
      const curAddr = (S.state && S.state.settings.address) || '';
      return `<section class="info-sec" style="margin-top:20px">
      <h3>بهینه‌ساز هوشمند — بهترین و سریع‌ترین تنظیمات برای شبکه گوشی شما</h3>
      <p style="font-size:12px;color:#9d9d9d;margin:6px 0 14px;line-height:2">فقط <b>یک دکمه</b> بزنید؛ سنجش از داخل مرورگر گوشی شما (یعنی دقیقاً روی اینترنت خودتان) انجام می‌شود: اپراتور تشخیص داده می‌شود، همه لبه‌های نزدیک ایران (IPv4 و IPv6) چند بار پینگ می‌شوند، <b>سریع‌ترین و کم‌نوسان‌ترین</b> لبه انتخاب و روی همه کانفیگ‌ها اعمال می‌شود، پروفایل ضد فیلتر اپراتور شما (FinalMask) و <b>بسته سرعت (Mux + KeepAlive)</b> هم خودکار فعال می‌گردد.</p>
      <label class="field sel" style="max-width:280px;margin-bottom:10px"><select id="scan-fam">
        <option value="auto" selected>خانواده IP: خودکار (IPv4 + IPv6)</option>
        <option value="4">فقط IPv4</option>
        <option value="6">فقط IPv6</option>
      </select></label>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" id="opt-all" style="box-shadow:0 0 0 1px #7fb98a inset">🌐 بهینه‌سازی همه‌اپراتوره — پکت‌لاست ۰ · پینگ پایین · سرعت بالا</button>
        <button class="btn primary" id="opt-run">بهینه‌سازی حداکثری (بهترین IP + سریع‌ترین تنظیمات)</button>
        <button class="btn" id="opt-speed">فقط تنظیمات پرسرعت (بدون اسکن)</button>
        <button class="btn" id="opt-stab">تست پایداری مسیر فعلی</button>
        <button class="btn" id="opt-stop" hidden>توقف</button>
      </div>
      <p style="font-size:11px;color:#8d8d8d;margin:8px 0 0;line-height:1.9">🌐 <b>همه‌اپراتوره:</b> برای وقتی که کانفیگ‌ها برای بعضی اپراتورها (مثلاً همراه اول یا ایرانسل) کند یا قطع است. هر لبه از <b>دو طرف</b> سنجیده می‌شود — پینگ و <b>پکت‌لاست</b> از گوشی شما، سرعت و مسیر تا سرور از خود سرور — و لبه‌های با <b>پکت‌لاست ۰ و کم‌ترین پینگ کل</b> انتخاب می‌شوند. بعد از آن، اشتراک همه کاربران به‌جای یک IP، <b>چند مسیر برتر + مسیر DNS خودکار</b> را حمل می‌کند؛ کلاینت هر کاربر (روی هر اپراتوری) خودش سریع‌ترین را برمی‌گزیند.</p>
      ${curAddr ? `<p style="font-size:11px;color:#7fb98a;margin-top:10px">مسیر فعلی: <b style="font-family:var(--mono);direction:ltr;display:inline-block">${esc(curAddr)}</b> — برای برگشت به مسیر دامنه، در «تنظیمات ← آدرس» مقدار را خالی کنید.</p>` : ''}
      ${(S.state && S.state.settings.multi_edge && S.state.settings.top_edges && S.state.settings.top_edges.length) ? `<p style="font-size:11px;color:#7fb98a;margin-top:6px">✓ حالت همه‌اپراتوره فعال است: اشتراک‌ها شامل <b>${S.state.settings.top_edges.length} مسیر برتر</b> + مسیر DNS خودکار هستند — روی هر اپراتوری کار می‌کند.</p>` : ''}
      <div class="progress" hidden id="opt-prog"><i></i></div>
      <p id="opt-status" style="font-size:11.5px;color:#8d8d8d;margin:8px 0 0;line-height:1.9"></p>
      <div id="opt-result"></div>
      <div id="opt-cands" style="margin-top:6px"></div>
      </section>
      <section class="info-sec" style="margin-top:20px">
      <h3>اسکن دستی لبه‌ها</h3>
      <p style="font-size:12px;color:#9d9d9d;margin:6px 0 14px;line-height:2">پینگ لبه‌های bunny.net (CDN خود Lucity) از <b>مرورگر خودتان</b> سنجیده می‌شود تا دقیقاً مطابق مسیر اینترنت شما باشد. لبه‌های نزدیک ایران (ترکیه، قفقاز، عراق، اروپا) اولویت دارند. با گزینه «خانواده IP» می‌توانید فقط IPv6 یا هر دو را اسکن کنید. روی «اعمال» بزنید تا همه کانفیگ‌ها از آن IP سرو شوند؛ برای برگشت، در «تنظیمات ← آدرس» مقدار را خالی کنید.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" id="scan-bunny">اسکن لبه‌های CDN</button>
        <button class="btn" id="scan-custom">اسکن IP های دلخواه (IPv4 / IPv6)</button>
        <button class="btn" id="scan-stop" hidden>توقف اسکن</button>
      </div>
      <div class="progress" hidden id="scan-prog"><i></i></div>
      <p id="scan-status" style="font-size:11.5px;color:#8d8d8d;margin:8px 0 0;line-height:1.9"></p>
      <div class="scan-list" id="scan-out"></div>
      </section>`;
    },
    stats() {
      const st = S.stats || {};
      const memStr = (st.mem_total || 0) >= 1024 ? ((st.mem_used || 0) / 1024).toFixed(1) + ' / ' + ((st.mem_total || 0) / 1024).toFixed(1) + ' GB' : (st.mem_used || 0) + ' / ' + (st.mem_total || 0) + ' MB';
      // v3.6: sv-* ids → statLoop refreshes these IN PLACE every second
      // (paintStats) instead of re-rendering the whole view every 5s.
      return `<section class="info-sec" style="margin-top:20px">
      <h3>آمار زنده سرور</h3>
      <ul class="kv">
      <li><span>پردازنده</span><b>${esc(st.cpu_model || '—')}</b></li>
      <li><span>مصرف CPU</span><b id="sv-cpu">${(st.cpu || 0).toFixed(1)}%</b></li>
      <li><span>حافظه</span><b id="sv-mem">${memStr} (${(Number(st.mem) || 0).toFixed(1)}%)</b></li>
      <li><span>دیسک</span><b id="sv-disk">${(st.disk && st.disk.used || 0)} / ${(st.disk && st.disk.total || 0)} GB</b></li>
      <li><span>دانلود کل</span><b id="sv-dl">${fmtGB(st.rx_total || 0)}</b></li>
      <li><span>آپلود کل</span><b id="sv-ul">${fmtGB(st.tx_total || 0)}</b></li>
      <li><span>ترافیک ۳۰ روز</span><b id="sv-t30">${st.traffic30 && st.traffic30.bytes ? fmtGB(st.traffic30.bytes) : '—'}</b></li>
      <li><span>کانال‌های فعال</span><b id="sv-online">${st.online || 0}</b></li>
      <li><span>کاربران آنلاین</span><b id="sv-onl-users">${st.online_users || 0}</b></li>
      <li><span>زمان روشن</span><b id="sv-up">${fmtUptime(st.uptime || 0)}</b></li>
      <li><span>نسخه</span><b>v${VER}</b></li></ul></section>`;
    },
    tools() {
      return `<section class="info-sec" style="margin-top:20px">
      <h3>ابزارها</h3>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
      <button class="btn" id="t-restart">ری‌استارت Xray</button>
      <button class="btn" id="t-config">دانلود کانفیگ سرور</button>
      <button class="btn" id="t-log">لاگ Xray</button>
      <button class="btn" id="t-restore">بازیابی پشتیبان</button>
      <button class="btn" id="t-reset">صفر کردن ترافیک همه</button>
      </div>
      <pre id="t-out" style="display:none;margin-top:14px;background:#0d0d0d;border:1px solid var(--line);border-radius:10px;padding:12px;font-size:10.5px;max-height:340px;overflow:auto;direction:ltr;text-align:left;white-space:pre-wrap"></pre>
      </section>`;
    },
    settings() {
      const st = S.state; if (!st) return '<p>در حال بارگذاری…</p>';
      const s = st.settings, ops = s.operators || {}, t = s.tuning || {};
      const cps = st.cipher_presets || {}, fps = st.fps || [];
      return `<section class="info-sec" style="margin-top:20px;max-width:720px">
      <h3>تنظیمات</h3>
      <h4 style="margin:16px 0 8px;font-size:12.5px;color:#cfcfcf">مدیریت</h4>
      <div class="row2">
      <label class="field"><input id="se-user" value="${esc(s.user || '')}" placeholder="نام کاربری"></label>
      <label class="field"><input id="se-pass" type="password" placeholder="رمز عبور جدید (خالی = بدون تغییر)"></label>
      </div>
      <div class="row2">
      <label class="field"><input id="se-session" type="number" min="1" max="336" value="${s.session_hours || 12}" placeholder="مدت نشست (ساعت ۱-۳۳۶)"></label>
      <label class="field"><input id="se-sni-ov" value="${esc(s.sni_override || '')}" placeholder="SNI جایگزین (اختیاری)"></label>
      </div>
      <h4 style="margin:16px 0 8px;font-size:12.5px;color:#cfcfcf">اتصال</h4>
      <div class="row2">
      <label class="field"><input id="se-address" value="${esc(s.address || '')}" placeholder="آدرس تمیز (IP یا دامنه)"></label>
      <label class="field"><input id="se-sni" value="${esc(s.reality_sni || '')}" placeholder="SNI برای Reality"></label>
      </div>
      <label class="field" style="margin:10px 0"><input id="se-fmt" value="${esc(s.cfg_fmt || '')}" placeholder="قالب نام کانفیگ ({name}-{label})"></label>
      <label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;margin:8px 2px"><input type="checkbox" id="se-randsni" ${s.random_sni ? 'checked' : ''}><span class="cbx"></span>SNI تصادفی ضد فیلتر (فقط *.lucity.app)</label>

      <h4 style="margin:18px 0 8px;font-size:12.5px;color:#cfcfcf">ربات تلگرام — اجرای پنل داخل تلگرام</h4>
      <p style="font-size:11px;color:#8d8d8d;margin-bottom:10px;line-height:2">در تلگرام به <b>@BotFather</b> بفرستید <code style="font-family:var(--mono)">/newbot</code>، اسم و یوزرنیم بدهید و <b>توکن</b> را کپی کنید. شناسه عددی خود را هم از <b>@userinfobot</b> بگیرید. بعد از «اتصال ربات»، دکمه منوی ربات و دستور <code style="font-family:var(--mono)">/start</code> خودکار ساخته می‌شوند و پنل مستقیم داخل تلگرام باز می‌شود — بدون نیاز به رمز.</p>
      <div class="row2">
      <label class="field"><input id="se-tg-token" type="password" placeholder="توکن ربات (123456789:AAF...)" autocomplete="off"></label>
      <label class="field"><input id="se-tg-admin" inputmode="numeric" placeholder="شناسه عددی تلگرام شما" autocomplete="off"></label>
      </div>
      <div class="btns" style="margin-top:6px">
        <button class="btn" id="tg-connect">اتصال ربات</button>
        <button class="btn" id="tg-disconnect" style="display:none">قطع اتصال</button>
      </div>
      <p id="tg-status" style="font-size:11.5px;color:#9d9d9d;margin-top:10px;line-height:2"></p>

      <h4 style="margin:18px 0 8px;font-size:12.5px;color:#cfcfcf">پروتکل‌ها</h4>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px">
      ${st.protocols.map(p => `<label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;background:rgba(255,255,255,.025);border:1px solid var(--line);border-radius:10px;padding:9px 12px">
        <input type="checkbox" class="se-proto" data-k="${p.key}" ${(s.protocols || {})[p.key] ? 'checked' : ''}><span class="cbx"></span>${esc(p.name)}</label>`).join('')}
      </div>

      <h4 style="margin:18px 0 8px;font-size:12.5px;color:#cfcfcf">FinalMask &amp; Cipher Suites — بهینه‌سازی و پایداری برای اپراتور شما</h4>
      <p style="font-size:11px;color:#8d8d8d;margin-bottom:10px;line-height:1.9"><b>FinalMask</b> دست دادن TLS را تکه‌تکه می‌کند (فرگمنت) و اثر انگشت TLS را شبیه مرورگر واقعی می‌کند تا DPI اپراتور نتواند پروکسی را تشخیص دهد و سرعت را نکَند. <b>Cipher Suites و ALPN</b> هم امضای رمزنگاری اتصال را عوض می‌کنند. کافی است فقط <b>Enable</b> را روشن کنید و اپراتور خود را انتخاب کنید — بقیه مقادیر بهترین حالت را می‌گیرند.</p>
      <label style="display:flex;gap:9px;align-items:center;font-size:12.5px;color:#e4e4e4;margin:10px 2px"><input type="checkbox" id="se-fm-on" ${t.enabled !== false ? 'checked' : ''}><span class="cbx"></span><b>Enable — فعال‌سازی FinalMask &amp; Cipher Suites</b></label>
      <div class="row2" style="margin-top:10px">
      <label class="field sel"><select id="se-opprof">
        ${Object.entries(ops).map(([k, o]) => `<option value="${k}" ${k === (t.profile || 'auto') ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}
      </select></label>
      <label class="field sel"><select id="se-fp">
        ${(fps.length ? fps : ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized']).map(f => `<option value="${f}" ${f === (t.fp || 'chrome') ? 'selected' : ''}>${esc(fpLabels[f] || f)}</option>`).join('')}
      </select></label>
      </div>
      <p id="se-opnote" style="font-size:11px;color:#8d8d8d;margin:8px 2px;line-height:1.9">${esc((ops[t.profile || 'auto'] || {}).note || '')}</p>

      <div id="fm-block">
        <h4 style="margin:16px 0 8px;font-size:12px;color:#cfcfcf">فرگمنت TLS (FinalMask)</h4>
        <label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;margin:6px 2px"><input type="checkbox" id="se-fragon" ${t.frag_on ? 'checked' : ''}><span class="cbx"></span>فرگمنت TLS فعال (پروفایل «خودکار» بدون فرگمنت کم‌ترین پینگ را دارد)</label>
        <div class="row2">
        <label class="field"><input id="se-fraglen" value="${esc(t.frag_lengths || '100-200')}" placeholder="طول فرگمنت (مثلاً 40-100)"></label>
        <label class="field"><input id="se-fragdelay" value="${esc(t.frag_delays || '10-20')}" placeholder="تأخیر فرگمنت به میلی‌ثانیه"></label>
        </div>
        <div class="row2">
        <label class="field sel"><select id="se-fragpackets">
          <option value="tlshello" ${(t.frag_packets || 'tlshello') === 'tlshello' ? 'selected' : ''}>تکه‌تکه کردن دست‌دادن TLS (توصیه‌شده)</option>
          <option value="1-3" ${t.frag_packets === '1-3' ? 'selected' : ''}>بسته‌های ۱ تا ۳</option>
        </select></label>
        <label class="field"><input id="se-fragmaxsplit" value="${esc(t.frag_maxsplit || '3-6')}" placeholder="بیشینه تکه (3-6)"></label>
        </div>

        <h4 style="margin:16px 0 8px;font-size:12px;color:#cfcfcf">Cipher Suites &amp; ALPN</h4>
        <div class="row2">
        <label class="field sel"><select id="se-alpn">
          ${['', 'http/1.1', 'h2', 'h2,http/1.1', 'http/1.1,h2'].map(m => `<option value="${m}" ${m === (t.alpn || '') ? 'selected' : ''}>${esc(alpnLabels[m] !== undefined ? alpnLabels[m] : m)}</option>`).join('')}
        </select></label>
        <label class="field sel"><select id="se-cipher">
          <option value="" ${!t.cipher_suites ? 'selected' : ''}>Cipher پیش‌فرض امن (توصیه‌شده)</option>
          ${Object.entries(cps).map(([k, v]) => `<option value="${esc(v)}" ${v === t.cipher_suites ? 'selected' : ''}>${esc(cipherLabels[k] || k)}</option>`).join('')}
          <option value="__custom__" ${t.cipher_suites && !Object.values(cps).includes(t.cipher_suites) ? 'selected' : ''}>اختصاصی…</option>
        </select></label>
        </div>
        <label class="field" id="se-cipher-wrap" style="display:none"><input id="se-cipher-custom" value="${esc(t.cipher_suites || '')}" placeholder="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"></label>

        <h4 style="margin:16px 0 8px;font-size:12px;color:#cfcfcf">نویز تصادفی (اختیاری — ضد تشخیص الگو)</h4>
        <label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;margin:6px 2px"><input type="checkbox" id="se-noiseon" ${t.noise_on ? 'checked' : ''}><span class="cbx"></span>افزودن بسته‌های نویز تصادفی به اتصال</label>
        <div class="row2">
        <label class="field"><input id="se-noiserand" value="${esc(t.noise_rand || '1-64')}" placeholder="اندازه بسته نویز (1-64)"></label>
        <label class="field"><input id="se-noisedelay" value="${esc(t.noise_delay || '10-20')}" placeholder="فاصله نویز به میلی‌ثانیه"></label>
        </div>
      </div>
      <div class="btns"><button class="btn primary" id="se-save">ذخیره تنظیمات</button></div>
      </section>`;
    },
    support() {
      return `<section class="info-sec" style="margin-top:20px;max-width:640px">
      <h3>پشتیبانی</h3>
      <p style="font-size:12.5px;color:#bbb;line-height:2.2;margin-top:8px">
      DEEP NETWORK روی Lucity اجرا می‌شود؛ همه‌ی تنظیمات از متغیرهای محیطی سرویس خوانده می‌شود:<br>
      <code style="font-family:var(--mono);direction:ltr;display:inline-block">ADMIN_PASSWORD</code> — رمز ورود به پنل (در غیر این صورت خودکار ساخته و در لاگ دیپلوی چاپ می‌شود)<br>
      <code style="font-family:var(--mono);direction:ltr;display:inline-block">DOMAIN</code> — دامنه سرویس (برای لینک‌های درست و اسکنر CDN)<br>
      <code style="font-family:var(--mono);direction:ltr;display:inline-block">UUID / SECRET</code> — ثابت نگه‌داشتن شناسه‌ها بین دیپلوی‌ها<br>
      <b style="color:#e8e8e8">مهم:</b> یک Volume روی مسیر <code style="font-family:var(--mono);direction:ltr;display:inline-block">/data</code> متصل کنید تا کاربران و لینک‌ها بعد از دیپلوی دوباره از بین نروند.</p>
      </section>`;
    },
  };

  const viewsInit = {
    users() {
      $('#add-user').addEventListener('click', () => renderView('create'));
      $('#export-backup').addEventListener('click', () => location.href = '/panel/api/backup');
      $$('#all-users .u-act button').forEach(b => b.addEventListener('click', async () => {
        const id = b.closest('.tr').dataset.id, act = b.dataset.act;
        const c = S.state.clients.find(x => x.id === id);
        if (act === 'sub') {
          modal(`<h3>اشتراک ${esc(c.name)} <button>✕</button></h3>
          <div class="linkbox"><span>${esc(c.sub_url)}</span><button id="m-copy"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button></div>
          <div class="qr-box"><img src="/panel/api/qr?data=${encodeURIComponent(c.sub_url)}" alt="QR"></div>
          <p style="font-size:11px;color:#8d8d8d">در v2rayNG: Import from clipboard — در Hiddify: + و سپس Paste</p>
          <div style="margin-top:12px"><small style="font-size:10.5px;color:#7fb98a">JSON بهینه — پرسرعت‌ترین (Mux فعال)</small>
          <div class="linkbox" style="margin-top:4px"><span>${esc(c.sub_url)}?fmt=xray</span><button id="m-copy-json"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button></div>
          <p style="font-size:11px;color:#8d8d8d">لینک را در مرورگر باز کنید، JSON را کپی کنید و در v2rayNG: + ← «Import config from clipboard»</p></div>`);
          $('#m-copy').addEventListener('click', () => copy(c.sub_url));
          $('#m-copy-json').addEventListener('click', () => copy(c.sub_url + '?fmt=xray'));
        } else if (act === 'edit') {
          const p = c.protocols || [];
          modal(`<h3>ویرایش ${esc(c.name)} <button>✕</button></h3>
          <label class="field"><input id="eu-name" value="${esc(c.name)}" placeholder="نام"></label>
          <div class="row2">
            <label class="field"><input id="eu-days" type="number" min="0" placeholder="روز (۰ = نامحدود)" value="${c.days_left || 0}"></label>
            <label class="field"><input id="eu-quota" type="number" min="0" placeholder="حجم GB" value="${c.quota ? Math.round(c.quota / 1073741824) : 0}"></label>
          </div>
          <label class="field"><input id="eu-note" value="${esc(c.note || '')}" placeholder="یادداشت"></label>
          <label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;margin:8px 2px"><input type="checkbox" id="eu-reset"><span class="cbx"></span>صفر کردن مصرف</label>
          <div class="btns"><button class="btn primary" id="eu-save">ذخیره</button></div>`);
          $('#eu-save').addEventListener('click', async () => {
            try {
              await api('clients/edit', { id, name: $('#eu-name').value, note: $('#eu-note').value,
                days: +$('#eu-days').value || 0, quota: (+$('#eu-quota').value || 0) * 1073741824, reset_usage: $('#eu-reset').checked });
              $('#modal-root').innerHTML = ''; toast('ذخیره شد ✓', 'ok'); refreshAll();
            } catch (ex) { toast(ex.message, 'err'); }
          });
        } else if (act === 'del') {
          if (!confirm('کاربر «' + c.name + '» حذف شود؟')) return;
          try { await api('clients/delete', { id }); toast('حذف شد', 'ok'); refreshAll(); } catch (ex) { toast(ex.message, 'err'); }
        }
      }));
    },
    create() {
      $('#nu-go').addEventListener('click', async () => {
        try {
          const r = await api('clients', { name: $('#nu-name').value, days: +$('#nu-days').value || 0, quota: (+$('#nu-quota').value || 0) * 1073741824, note: $('#nu-note').value });
          toast('کاربر ساخته شد ✓', 'ok'); refreshAll(); renderView('users');
        } catch (ex) { toast(ex.message, 'err'); }
      });
    },
    subs() {
      $$('[data-copy]').forEach(b => b.addEventListener('click', () => copy(b.dataset.copy)));
      $$('[data-qr]').forEach(b => b.addEventListener('click', () => {
        modal(`<h3>QR اشتراک <button>✕</button></h3><div class="qr-box"><img src="/panel/api/qr?data=${encodeURIComponent(b.dataset.qr)}" alt="QR"></div>`);
      }));
    },
    scanner() {
      // ── shared probe helper (used by optimizer, stability test and manual scan) ──
      const TIMEOUT = 3500;
      const timedFetch = (url, ms) => new Promise(resolve => {
        let ctl;
        try { ctl = new AbortController(); } catch { resolve(); return; }
        const t = setTimeout(() => { try { ctl.abort(); } catch { } }, ms);
        fetch(url, { mode: 'no-cors', cache: 'no-store', signal: ctl.signal })
          .catch(() => { })
          .finally(() => { clearTimeout(t); resolve(); });
      });
      const probe = async (host, ms) => {
        const t0 = performance.now();
        // IPv6 literals must be bracketed in URLs (https://[2400:52e0::1]/)
        const h = (String(host).includes(':') && !String(host).startsWith('[')) ? '[' + host + ']' : host;
        await timedFetch('https://' + h + '/', ms || TIMEOUT);
        return Math.round(performance.now() - t0);
      };
      const median = a => a.slice().sort((x, y) => x - y)[Math.floor(a.length / 2)];
      const jitter = a => a.length < 2 ? 0 : Math.max(...a) - Math.min(...a);
      const jitterVerdict = j => j <= 25 ? '<b style="color:var(--ok)">بسیار پایدار</b>' : j <= 60 ? '<b style="color:#d6c96b">پایدار</b>' : '<b style="color:#f8b4b4">نوسان بالا</b>';

      // IP family selector (v3.7): "auto" = IPv4 + IPv6 merged, "6" = IPv6 only
      const famVal = () => { const s = $('#scan-fam'); return s ? s.value : 'auto'; };
      const loadEdges = async () => {
        const fam = famVal();
        const geo = {};
        let edges = [];
        const grab = async f => {
          try {
            const r = await api('bunnyedges?family=' + f, {});
            (r.edges || []).forEach(e => edges.push(e));
            Object.assign(geo, r.geo || {});
          } catch { /* family unavailable on this deploy */ }
        };
        if (fam === '6') { await grab('6'); }
        else {
          await grab('4');
          if (fam === 'auto') {
            // only sweep v6 if this phone actually has IPv6 — quick 1-edge probe
            try {
              const probe6 = await api('bunnyedges?family=6', {});
              const cand = (probe6.edges || [])[0];
              if (cand) { const ms = await probe(cand, 1800); if (ms < 1700) await grab('6'); }
            } catch { }
          }
        }
        return { edges, geo };
      };

      // ─────────── SMART OPTIMIZER — one button: best IP + operator tuning ───────────
      const oStatus = $('#opt-status'), oProg = $('#opt-prog'), oRes = $('#opt-result'),
        oCands = $('#opt-cands'), oStop = $('#opt-stop'), oRun = $('#opt-run');
      // guard: placeholder render (state not yet arrived) has none of these elements
      if (!oRun || !oStatus || !oStop || !$('#scan-bunny')) return;
      let optStop = false;
      oStop.addEventListener('click', () => { optStop = true; });
      const setStep = (txt, pct) => {
        oStatus.innerHTML = txt;
        if (pct == null) { oProg.hidden = true; } else { oProg.hidden = false; const b = $('i', oProg); if (b) b.style.width = pct + '%'; }
      };
      const runMap = async (list, fn, conc, onOne) => {
        const q = list.slice(); let done = 0;
        await Promise.all(Array.from({ length: conc }, async () => {
          while (!optStop) {
            const it = q.shift(); if (!it) return;
            await fn(it); done++;
            if (onOne) onOne(it, done);
          }
        }));
      };

      $('#opt-run').addEventListener('click', async () => {
        if (oRun.dataset.busy === '1') return;
        oRun.dataset.busy = '1'; oRun.disabled = true; optStop = false;
        oStop.hidden = false; oRes.innerHTML = ''; oCands.innerHTML = '';
        try {
          // 1) operator detect (server reads the request IP → ASN)
          setStep('۱/۵ — تشخیص اپراتور اینترنت شما…', 5);
          let w; try { w = await api('whoami'); } catch { w = { operator: 'auto', label: 'خودکار' }; }
          const opKey = (w.operator && w.operator !== 'auto') ? w.operator : 'auto';
          const opLabel = opKey === 'auto' ? 'خودکار' : (w.label || opKey);

          // 2) verified geo-balanced edges (IPv4 + IPv6 per family selector)
          setStep('۲/۵ — دریافت لبه‌های تأییدشده نزدیک ایران… (اولین بار ممکن است تا ۳۰ ثانیه طول بکشد)', 15);
          const { edges: allEdges, geo } = await loadEdges();
          const edges = allEdges.slice(0, famVal() === 'auto' ? 60 : 40);
          if (!edges.length) { setStep(''); oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">هیچ لبه‌ای تأیید نشد — DOMAIN را چک کنید.</p>'; return; }
          const r = { geo };

          // 3) round 1 — first RTT sweep from THIS phone
          setStep('۳/۵ — سنجش پینگ ' + edges.length + ' لبه از مرورگر شما…', 20);
          const first = new Map();
          await runMap(edges, async ip => { first.set(ip, await probe(ip)); }, 6,
            (ip, done) => setStep('۳/۵ — سنجش پینگ ' + done + ' از ' + edges.length + ' لبه…', 20 + done / edges.length * 40));
          const alive = edges.filter(ip => (first.get(ip) || TIMEOUT) < TIMEOUT - 50)
            .sort((a, b) => first.get(a) - first.get(b)).slice(0, 12);
          if (!alive.length) {
            setStep('');
            const noV6 = famVal() === '6';
            oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + (noV6
              ? 'هیچ لبه IPv6 از اینترنت شما پاسخ نداد — به نظر می‌رسد شبکه شما IPv6 ندارد؛ گزینه «فقط IPv4» را انتخاب کنید.'
              : 'هیچ لبه‌ای از اینترنت شما پاسخ نداد — بعداً دوباره تلاش کنید.') + '</p>';
            return;
          }

          // 4) rounds 2-3 on the top 12 → median + jitter (stability!)
          setStep('۴/۵ — سنجش پایداری ۱۲ لبه برتر (هرکدام ۳ بار)…', 65);
          const samples = new Map(alive.map(ip => [ip, [first.get(ip)]]));
          for (let round = 0; round < 2 && !optStop; round++) {
            await runMap(alive, async ip => { samples.get(ip).push(await probe(ip)); }, 6);
          }
          const cands = alive.map(ip => {
            const s = samples.get(ip);
            return { ip, geo: (r.geo || {})[ip] || null, med: median(s), jit: jitter(s) };
          }).map(c => ({ ...c, score: c.med + c.jit * 0.6 })).sort((a, b) => a.score - b.score);
          oCands.innerHTML = '<p style="font-size:11px;color:#8d8d8d;margin:2px 0 6px">برترین گزینه‌ها (پینگ میانه + نوسان):</p>' +
            cands.slice(0, 5).map((c, i) => `<div class="scan-row"><span>${i === 0 ? '🏆 ' : ''}${c.ip}</span>
              <span class="ok">${c.med} ms</span><span class="geo">نوسان ${c.jit} ms · ${c.geo ? esc(c.geo.city + '، ' + c.geo.cc) : '—'}</span>
              <span class="geo">${i === 0 ? 'انتخاب شد' : 'رزرو'}</span></div>`).join('');

          // 5) confirm the winner (2 extra probes), fall back if it died
          setStep('۵/۵ — تأیید نهایی و اعمال روی همه کانفیگ‌ها…', 88);
          let best = null;
          for (const c of cands) {
            const c1 = await probe(c.ip), c2 = await probe(c.ip);
            if (c1 < TIMEOUT - 50 && c2 < TIMEOUT - 50) { best = { ...c, med: median([c.med, c1, c2]) }; break; }
          }
          if (optStop) { setStep('بهینه‌سازی متوقف شد.'); return; }
          if (!best) { setStep(''); oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">هیچ لبه‌ای پایدار پاسخ نداد — دوباره تلاش کنید.</p>'; return; }

          // apply: best edge IP + operator FinalMask profile + SPEED PACK in one shot
          const tuning = { enabled: true, profile: opKey, frag_on: opKey !== 'auto', mux_off: false, noise_on: false };
          await api('settings', { address: best.ip, tuning });
          await refreshAll();
          setStep('انجام شد ✓', null);
          oRes.innerHTML = `<div class="opt-ok">
            <b style="font-size:13px">بهترین مسیر و سریع‌ترین تنظیمات برای شبکه شما فعال شد ✓</b>
            <ul class="kv" style="margin-top:8px">
            <li><span>اپراتور شناسایی‌شده</span><b>${esc(opLabel)}</b></li>
            <li><span>پروفایل FinalMask اعمال‌شده</span><b>${opKey === 'auto' ? 'خودکار (بدون فرگمنت — کم‌ترین پینگ)' : esc(opLabel)}</b></li>
            <li><span>بهترین لبه</span><b style="font-family:var(--mono);direction:ltr;display:inline-block">${best.ip}</b>${best.ip.includes(':') ? ' <span class="badge" style="font-size:10px">IPv6</span>' : ''}</li>
            <li><span>موقعیت</span><b>${best.geo ? esc(best.geo.city + '، ' + best.geo.cc) : '—'}</b></li>
            <li><span>پینگ میانه</span><b style="color:var(--ok)">${best.med} ms</b></li>
            <li><span>نوسان (پایداری)</span><b>${best.jit} ms — ${jitterVerdict(best.jit)}</b></li>
            <li><span>بسته سرعت</span><b style="color:var(--ok)">Mux فعال + KeepAlive سریع ✓</b></li>
            </ul>
            <p style="font-size:11px;color:#8d8d8d;line-height:2;margin-top:8px">همه کانفیگ‌ها حالا از این لبه با سریع‌ترین تنظیمات سرو می‌شوند. در کلاینت خود (v2rayNG / Hiddify) اشتراک را <b>به‌روزرسانی (Update)</b> کنید تا لینک‌های جدید گرفته شود. برای بیشترین سرعت، از بخش «اشتراک‌ها» لینک <b>JSON بهینه</b> را هم می‌توانید مستقیم وارد کلاینت کنید. اگر باز هم قطع و وصل شد، دوباره همین دکمه را بزنید تا لبه تازه‌ای انتخاب شود.</p></div>`;
        } catch (ex) {
          setStep('');
          oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + esc(ex.message) + '</p>';
        } finally {
          oRun.dataset.busy = '0'; oRun.disabled = false; oStop.hidden = true;
        }
      });

      // ─────────── SPEED-ONLY BUTTON: apply the fastest settings without scanning ───────────
      $('#opt-speed').addEventListener('click', async () => {
        const btn = $('#opt-speed');
        if (btn.dataset.busy === '1') return;
        btn.dataset.busy = '1'; btn.disabled = true;
        try {
          setStep('تشخیص اپراتور و اعمال بسته سرعت روی همه کانفیگ‌ها…', 40);
          let w; try { w = await api('whoami'); } catch { w = { operator: 'auto' }; }
          const opKey = (w.operator && w.operator !== 'auto') ? w.operator : 'auto';
          const opLabel = opKey === 'auto' ? 'خودکار' : (w.label || opKey);
          await api('settings', { tuning: { enabled: true, profile: opKey, frag_on: opKey !== 'auto', mux_off: false, noise_on: false } });
          await refreshAll();
          setStep('بسته سرعت اعمال شد ✓', null);
          oRes.innerHTML = `<div class="opt-ok">
            <b style="font-size:13px">سریع‌ترین تنظیمات روی همه کانفیگ‌ها اعمال شد ✓</b>
            <ul class="kv" style="margin-top:8px">
            <li><span>اپراتور شناسایی‌شده</span><b>${esc(opLabel)}</b></li>
            <li><span>Mux (چند جریان روی یک اتصال)</span><b style="color:var(--ok)">فعال — concurrency 8 ✓</b></li>
            <li><span>KeepAlive تهاجمی + NoDelay</span><b style="color:var(--ok)">فعال ✓</b></li>
            <li><span>فرگمنت TLS</span><b>${opKey !== 'auto' ? 'روشن (مطابق پروفایل ' + esc(opLabel) + ')' : 'خاموش (کم‌ترین پینگ)'}</b></li>
            <li><span>نویز تصادفی</span><b>خاموش</b></li>
            </ul>
            <p style="font-size:11px;color:#8d8d8d;line-height:2;margin-top:8px">این دکمه مسیر (IP) فعلی را نگه می‌دارد و فقط تنظیمات سرعت را بهینه می‌کند. اگر پینگ هم بالاست، دکمه «بهینه‌سازی حداکثری» را بزنید. برای استفاده از Mux، لینک <b>JSON بهینه</b> را از بخش «اشتراک‌ها» در کلاینت وارد کنید یا اشتراک استاندارد را Update کنید.</p></div>`;
        } catch (ex) {
          setStep(''); toast(ex.message, 'err');
        } finally { btn.dataset.busy = '0'; btn.disabled = false; }
      });

      // ─────────── ALL-OPERATOR OPTIMIZER — 0 packet loss · low ping · high speed ───────────
      // Grades every edge from BOTH ends: browser (RTT + jitter + packet loss
      // over 6 probes) and server (edge→origin handshake + throughput via
      // /panel/api/edgespeed). Applies the winner as primary AND stores the
      // top-5 as fallback routes — the subscription then carries one entry per
      // edge + a DNS-auto entry, so every operator's clients pick their best.
      $('#opt-all').addEventListener('click', async () => {
        if (oRun.dataset.busy === '1') return;
        oRun.dataset.busy = '1'; oRun.disabled = true; optStop = false;
        oStop.hidden = false; oRes.innerHTML = ''; oCands.innerHTML = '';
        const medal = i => ['🥇', '🥈', '🥉'][i] || 'E' + (i + 1);
        try {
          // 1) operator detect (informational — this mode serves ALL operators)
          setStep('۱/۶ — تشخیص اپراتور شما (فقط برای گزارش)…', 3);
          let w; try { w = await api('whoami'); } catch { w = { operator: 'auto', label: 'خودکار' }; }
          const opKey = (w.operator && w.operator !== 'auto') ? w.operator : 'auto';
          const opLabel = opKey === 'auto' ? 'خودکار' : (w.label || opKey);

          // 2) verified geo-balanced edges
          setStep('۲/۶ — دریافت لبه‌های تأییدشده نزدیک ایران… (اولین بار تا ۳۰ ثانیه)', 8);
          const { edges: allEdges, geo } = await loadEdges();
          const edges = allEdges.slice(0, famVal() === 'auto' ? 60 : 40);
          if (!edges.length) { setStep(''); oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">هیچ لبه‌ای تأیید نشد — DOMAIN را چک کنید.</p>'; return; }

          // 3) round 1 — RTT sweep from THIS device
          setStep('۳/۶ — پینگ اولیه ' + edges.length + ' لبه از دستگاه شما…', 12);
          const first = new Map();
          await runMap(edges, async ip => { first.set(ip, await probe(ip)); }, 6,
            (ip, done) => setStep('۳/۶ — پینگ ' + done + ' از ' + edges.length + '…', 12 + done / edges.length * 22));
          const alive = edges.filter(ip => (first.get(ip) || TIMEOUT) < TIMEOUT - 50)
            .sort((a, b) => first.get(a) - first.get(b)).slice(0, 14);
          if (!alive.length) {
            setStep('');
            oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + (famVal() === '6'
              ? 'هیچ لبه IPv6 پاسخ نداد — شبکه شما احتمالاً IPv6 ندارد؛ «فقط IPv4» را انتخاب کنید.'
              : 'هیچ لبه‌ای از اینترنت شما پاسخ نداد — بعداً دوباره تلاش کنید.') + '</p>';
            return;
          }

          // 4) deep quality probe — 5 more rounds each → median, jitter, PACKET LOSS
          setStep('۴/۶ — سنجش دقیق پکت‌لاست و نوسان (' + alive.length + ' لبه برتر × ۶ پینگ)…', 36);
          const lost = ms => ms >= TIMEOUT - 50;
          const samples = new Map(alive.map(ip => [ip, [first.get(ip)]]));
          for (let round = 0; round < 5 && !optStop; round++) {
            await runMap(alive, async ip => { samples.get(ip).push(await probe(ip)); }, 6);
            setStep('۴/۶ — سنجش پکت‌لاست — دور ' + (round + 1) + ' از ۵…', 36 + (round + 1) / 5 * 20);
          }
          const graded = alive.map(ip => {
            const s = samples.get(ip);
            const ok = s.filter(x => !lost(x));
            const l = s.length ? Math.round((s.length - ok.length) / s.length * 1000) / 10 : 100;
            return { ip, geo: geo[ip] || null, med: ok.length ? median(ok) : TIMEOUT,
              jit: ok.length > 1 ? Math.max(...ok) - Math.min(...ok) : 0, loss: l };
          }).filter(c => c.loss < 80 && c.med < TIMEOUT);

          // 5) server-side: edge→origin handshake + real throughput through each edge
          setStep('۵/۶ — سنجش سرعت و مسیر هر لبه تا سرور (سمت سرور، از طریق همان لبه)…', 58);
          const spd = new Map();
          try {
            const r2 = await api('edgespeed', { targets: graded.map(c => c.ip), kb: 64 });
            (r2.results || []).forEach(x => { if (x.ok) spd.set(x.ip, x); });
          } catch { /* server-side leg unavailable — rank on browser data only */ }
          const rows = graded.map(c => {
            const sp = spd.get(c.ip) || {};
            const org = sp.hs_ms || 0, kbps = sp.kbps || 0;
            return { ...c, org, kbps, score: c.med + org * 0.35 + c.jit * 0.5 + c.loss * 8 };
          }).sort((a, b) => a.score - b.score);
          oCands.innerHTML = '<p style="font-size:11px;color:#8d8d8d;margin:2px 0 6px">جدول کیفیت لبه‌ها (پینگ شما + مسیر تا سرور + پکت‌لاست + سرعت):</p>' +
            rows.slice(0, 8).map((c, i) => `<div class="scan-row"><span>${medal(i)} ${c.ip}</span>
              <span class="ok">${Math.round(c.med)}ms</span>
              <span class="geo">کل ≈ ${Math.round(c.med + c.org)}ms${c.org ? ' · لبه→سرور ' + Math.round(c.org) + 'ms' : ''}</span>
              <span class="geo">${c.loss === 0 ? '<b style="color:var(--ok)">پکت‌لاست ۰</b>' : 'پکت‌لاست ' + c.loss + '٪'}${c.kbps ? ' · ' + c.kbps + ' KB/s' : ''} · نوسان ' + Math.round(c.jit) + 'ms</span>
              <span class="geo">${c.geo ? esc(c.geo.city + '، ' + c.geo.cc) : '—'}</span></div>`).join('');

          // 6) strict 0-loss gate, then apply
          const zeroLoss = rows.filter(r => r.loss === 0);
          const ranked = (zeroLoss.length >= 3 ? zeroLoss : rows).slice(0, 5);
          if (optStop) { setStep('بهینه‌سازی متوقف شد.'); return; }
          if (!ranked.length) { setStep(''); oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">هیچ لبه سالمی پیدا نشد — دوباره تلاش کنید.</p>'; return; }
          setStep('۶/۶ — اعمال بهینه‌سازی همه‌اپراتوره روی همه کانفیگ‌ها…', 92);
          await api('settings', {
            address: ranked[0].ip,
            random_sni: true, // SNI تصادفی زیر دامنه پلتفرم — فیلتر SNI همه اپراتورها را دور می‌زند
            top_edges: ranked.map(c => ({ ip: c.ip, med: c.med, jit: c.jit, loss: c.loss,
              origin_ms: c.org, kbps: c.kbps, score: c.score,
              cc: c.geo ? (c.geo.cc || '') : '', city: c.geo ? (c.geo.city || '') : '' })),
            multi_edge: true,
            tuning: { enabled: true, profile: opKey, frag_on: false, mux_off: false, noise_on: false }
          });
          await refreshAll();
          setStep('انجام شد ✓', null);
          const perfect = ranked.filter(r => r.loss === 0).length;
          oRes.innerHTML = `<div class="opt-ok">
            <b style="font-size:13px">بهینه‌سازی همه‌اپراتوره اعمال شد ✓ — ${perfect ? perfect + ' لبه با پکت‌لاست ۰' : 'بهترین لبه‌های موجود'} انتخاب شدند</b>
            <ul class="kv" style="margin-top:8px">
            <li><span>اپراتور شما (تشخیص‌داده‌شده)</span><b>${esc(opLabel)}</b></li>
            <li><span>مسیر اصلی (سریع‌ترین)</span><b style="font-family:var(--mono);direction:ltr;display:inline-block">${ranked[0].ip}</b>${ranked[0].ip.includes(':') ? ' <span class="badge" style="font-size:10px">IPv6</span>' : ''}</li>
            <li><span>پینگ شما تا مسیر اصلی</span><b style="color:var(--ok)">${Math.round(ranked[0].med)} ms</b></li>
            <li><span>مسیر کامل (لبه + سرور)</span><b>≈ ${Math.round(ranked[0].med + ranked[0].org)} ms</b></li>
            <li><span>پکت‌لاست مسیر اصلی</span><b style="color:${ranked[0].loss === 0 ? 'var(--ok)' : '#d6c96b'}">${ranked[0].loss}٪</b></li>
            <li><span>سرعت لبه تا سرور</span><b>${ranked[0].kbps ? Math.round(ranked[0].kbps) + ' KB/s' : '—'}</b></li>
            <li><span>مسیرهای پشتیبان در اشتراک</span><b>${ranked.length} مسیر + ۱ مسیر DNS خودکار</b></li>
            <li><span>SNI تصادفی (ضد فیلتر SNI)</span><b style="color:var(--ok)">روشن ✓</b></li>
            <li><span>فرگمنت (افزایش پینگ)</span><b style="color:var(--ok)">خاموش — کم‌ترین پینگ ✓</b></li>
            <li><span>بسته سرعت (Mux + KeepAlive)</span><b style="color:var(--ok)">فعال ✓</b></li>
            </ul>
            <p style="font-size:11px;color:#8d8d8d;line-height:2;margin-top:8px">حالا اشتراک هر کاربر به‌جای یک IP، <b>${ranked.length} مسیر برتر (🥇🥈🥉 با شهر و پینگ) + مسیر DNS خودکار</b> را شامل می‌شود؛ کلاینت روی <b>هر اپراتوری</b> (همراه اول، ایرانسل، رایتل، مخابرات، شاتل و…) خودش سریع‌ترین مسیر را پیدا می‌کند. در کلاینت خود (v2rayNG / Hiddify) اشتراک را <b>Update</b> کنید و اگر چند کانفیگ دیدید، عادی است — همه سالم‌اند؛ با «Real-delay test» سریع‌ترین را انتخاب کنید.</p></div>`;
        } catch (ex) {
          setStep('');
          oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + esc(ex.message) + '</p>';
        } finally {
          oRun.dataset.busy = '0'; oRun.disabled = false; oStop.hidden = true;
        }
      });

      // ─────────── STABILITY TEST of the current route ───────────
      $('#opt-stab').addEventListener('click', async () => {
        const btn = $('#opt-stab');
        if (btn.dataset.busy === '1') return;
        btn.dataset.busy = '1'; btn.disabled = true; optStop = false; oStop.hidden = false;
        try {
          const target = (S.state && S.state.settings.address) || location.host;
          setStep('سنجش پایداری مسیر فعلی (<b style="font-family:var(--mono);direction:ltr;display:inline-block">' + esc(target) + '</b>) — ۱۰ پینگ متوالی…', 10);
          const s = [];
          for (let i = 0; i < 10 && !optStop; i++) { s.push(await probe(target)); setStep('سنجش پایداری مسیر فعلی — ' + (i + 1) + ' از ۱۰…', (i + 1) / 10 * 100); }
          const lostN = s.filter(x => x >= TIMEOUT - 50).length;
          const okS = s.filter(x => x < TIMEOUT - 50);
          const med = okS.length ? median(okS) : TIMEOUT, jit = okS.length > 1 ? jitter(okS) : 0;
          const lossPct = Math.round(lostN / s.length * 1000) / 10;
          const lossVerdict = l => l === 0 ? '<b style="color:var(--ok)">پکت‌لاست ۰ ✓</b>' : l < 10 ? '<b style="color:#d6c96b">' + l + '٪</b>' : '<b style="color:#f8b4b4">' + l + '٪ — ناپایدار</b>';
          setStep('تست پایداری تمام شد', null);
          oRes.innerHTML = `<div class="opt-ok">
            <b style="font-size:13px">نتیجه تست مسیر فعلی</b>
            <ul class="kv" style="margin-top:8px">
            <li><span>مقصد</span><b style="font-family:var(--mono);direction:ltr;display:inline-block">${esc(target)}</b></li>
            <li><span>پینگ میانه</span><b>${Math.round(med)} ms</b></li>
            <li><span>کمترین / بیشترین</span><b>${okS.length ? Math.min(...okS) + ' / ' + Math.max(...okS) + ' ms' : '—'}</b></li>
            <li><span>نوسان</span><b>${Math.round(jit)} ms — ${jitterVerdict(jit)}</b></li>
            <li><span>پکت‌لاست (${s.length} پینگ)</span><b>${lossVerdict(lossPct)}</b></li>
            </ul>
            <p style="font-size:11px;color:#8d8d8d;line-height:2;margin-top:8px">${lossPct > 0 || jit > 60 || med > 400
              ? 'پکت‌لاست، نوسان یا پینگ بالاست — دکمه «🌐 بهینه‌سازی همه‌اپراتوره» را بزنید تا مسیرهای سالم (پکت‌لاست ۰) به اشتراک اضافه شوند.'
              : 'مسیر فعلی سالم است؛ اگر باز هم قطع و وصل می‌شود، «🌐 بهینه‌سازی همه‌اپراتوره» را اجرا کنید و اشتراک را در کلاینت به‌روزرسانی کنید.'}</p></div>`;
        } catch (ex) {
          setStep(''); oRes.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + esc(ex.message) + '</p>';
        } finally { btn.dataset.busy = '0'; btn.disabled = false; oStop.hidden = true; }
      });

      // ─────────── MANUAL SCAN (unchanged behavior) ───────────
      const out = $('#scan-out'), prog = $('#scan-prog'), statusEl = $('#scan-status'), stopBtn = $('#scan-stop');
      let stopped = false;
      stopBtn.addEventListener('click', () => { stopped = true; });

      // event delegation: ONE listener for every «اعمال» button (no re-attach churn)
      out.addEventListener('click', async e => {
        const b = e.target.closest('[data-ip]');
        if (!b) return;
        try {
          await api('settings', { address: b.dataset.ip });
          toast('IP روی همه کانفیگ‌ها اعمال شد ✓', 'ok'); refreshAll();
        } catch (ex) { toast(ex.message, 'err'); }
      });

      $('#scan-bunny').addEventListener('click', async () => {
        if (out.dataset.busy === '1') return;
        out.dataset.busy = '1'; stopped = false; stopBtn.hidden = false;
        const fam = famVal();
        statusEl.textContent = 'در حال دریافت لبه‌های تأییدشده' + (fam === '6' ? ' (IPv6)' : fam === 'auto' ? ' (IPv4 + IPv6)' : '') + '… (اولین اسکن ممکن است تا ۳۰ ثانیه طول بکشد؛ دفعات بعد سریع است)';
        out.innerHTML = '';
        try {
          const { edges: allE, geo } = await loadEdges();
          if (!allE.length) {
            statusEl.textContent = '';
            out.innerHTML = '<p style="color:#f8b4b4;font-size:12px">لبه‌ای تأیید نشد — DOMAIN را چک کنید.' + (fam === '6' ? ' یا شبکه شما IPv6 ندارد.' : '') + '</p>';
            return;
          }
          const CONC = 6; // capped parallelism — 40 hanging fetches used to saturate mobile links
          const edges = allE.slice(0, fam === 'auto' ? 70 : 60);
          const rows = edges.map(ip => ({ ip, geo: geo[ip] || null, ms: null }));
          const byIp = new Map(rows.map(x => [x.ip, x]));
          const renderRows = () => {
            const fin = rows.filter(x => x.ms != null).sort((a, b) => a.ms - b.ms);
            const pend = rows.filter(x => x.ms == null);
            const row = w => `<div class="scan-row"><span>${w.ip}</span>
            <span class="${w.ms == null ? '' : (w.ms < TIMEOUT - 50 ? 'ok' : 'bad')}">${w.ms == null ? '…' : (w.ms < TIMEOUT - 50 ? w.ms + ' ms' : 'بدون پاسخ')}</span>
            <span class="geo">${w.geo ? esc(w.geo.city + '، ' + w.geo.cc) : '—'}</span>
            <button class="mini-btn" data-ip="${w.ip}">اعمال</button></div>`;
            out.innerHTML = fin.map(row).join('') + pend.map(row).join('');
          };
          renderRows();
          prog.hidden = false;
          statusEl.textContent = '۰ از ' + rows.length + ' لبه بررسی شد…';
          let doneN = 0, okN = 0;
          const queue = edges.slice();
          await Promise.all(Array.from({ length: CONC }, async () => {
            while (!stopped) {
              const ip = queue.shift();
              if (!ip) return;
              const ms = await probe(ip);
              const rw = byIp.get(ip);
              if (rw) {
                rw.ms = Math.min(ms, TIMEOUT);
                if (ms < TIMEOUT - 50) okN++;
              }
              doneN++;
              const bar = $('i', prog); if (bar) bar.style.width = (doneN / rows.length * 100) + '%';
              statusEl.textContent = doneN + ' از ' + rows.length + ' لبه بررسی شد — ' + okN + ' لبه پاسخ داد';
              renderRows();
            }
          }));
          prog.hidden = true;
          statusEl.textContent = stopped
            ? 'اسکن متوقف شد — ' + doneN + ' لبه بررسی شد'
            : 'تمام شد ✓ سریع‌ترین لبه در بالای فهرست است — روی «اعمال» بزنید';
        } catch (ex) {
          statusEl.textContent = '';
          out.innerHTML = '<p style="color:#f8b4b4;font-size:12px">' + esc(ex.message) + '</p>';
        } finally {
          out.dataset.busy = '0'; stopBtn.hidden = true; prog.hidden = true;
        }
      });
      $('#scan-custom').addEventListener('click', () => {
        modal(`<h3>اسکن IP های دلخواه <button>✕</button></h3>
        <label class="field"><textarea id="sc-list" rows="4" style="width:100%;background:none;border:0;outline:0;color:#eee;font-family:var(--mono);font-size:11px" placeholder="1.2.3.4&#10;2400:52e0:1500::714:1&#10;5.6.7.8"></textarea>
        <div class="btns"><button class="btn primary" id="sc-go">اسکن (سمت سرور)</button></div>`);
        $('#sc-go').addEventListener('click', async () => {
          const targets = $('#sc-list').value.split('\n').map(s => s.trim()).filter(Boolean);
          if (!targets.length) return toast('حداقل یک IP وارد کنید', 'err');
          try {
            const r = await api('ipscan', { targets, port: 443 });
            $('#modal-root').innerHTML = '';
            const box = $('#scan-out'); // query AFTER the modal closes — the old `out` may be detached
            if (box) box.innerHTML = r.results.map(x => `<div class="scan-row"><span>${esc(x.target)}</span>
              <span class="${x.ok ? 'ok' : 'bad'}">${x.ok ? x.ms.toFixed(1) + ' ms' : 'غیرقابل دسترس'}</span><span></span><span></span></div>`).join('') || '<p style="color:#8d8d8d;font-size:12px">نتیجه‌ای نبود</p>';
          } catch (ex) { toast(ex.message, 'err'); }
        });
      });
    },
    tools() {
      $('#t-restart').addEventListener('click', async () => { try { await api('restart'); toast('Xray ری‌استارت شد ✓', 'ok'); } catch (ex) { toast(ex.message, 'err'); } });
      $('#t-config').addEventListener('click', () => location.href = '/panel/api/server-config');
      $('#t-log').addEventListener('click', async () => {
        try {
          const r = await api('log');
          const el = $('#t-out'); el.hidden = false; el.style.display = 'block';
          el.textContent = (r.lines || []).join('\n') || '(خالی)';
        } catch (ex) { toast(ex.message, 'err'); }
      });
      $('#t-reset').addEventListener('click', async () => {
        if (!confirm('مصرف همه کاربران صفر شود؟')) return;
        try { await api('reset-traffic-all'); toast('صفر شد ✓', 'ok'); refreshAll(); } catch (ex) { toast(ex.message, 'err'); }
      });
      $('#t-restore').addEventListener('click', () => {
        const i = document.createElement('input'); i.type = 'file'; i.accept = '.json';
        i.addEventListener('change', async () => {
          try {
            const txt = await i.files[0].text();
            await api('restore', { state: JSON.parse(txt).state });
            toast('بازیابی شد ✓', 'ok'); refreshAll();
          } catch (ex) { toast(ex.message, 'err'); }
        });
        i.click();
      });
    },
    settings() {
      // guard: when state hasn't arrived yet the view renders a placeholder that
      // has none of these elements — bail and let viewStale re-render + re-bind
      // once stateLoop delivers data (was: rare "textContent of null" race).
      if (!$('#tg-status') || !$('#se-save')) return;
      // ── Telegram bot section (v3.4) ──
      const stEl = $('#tg-status'), connBtn = $('#tg-connect'), discBtn = $('#tg-disconnect');
      const paintTg = () => {
        const tg = (S.state && S.state.settings && S.state.settings.telegram) || {};
        if (tg.connected) {
          stEl.innerHTML = '<b style="color:var(--ok)">متصل: @' + esc(tg.bot_username || '') + '</b> — حالا در تلگرام ربات را باز کنید و <b>/start</b> بزنید؛ پنل با دکمه منو یا دکمه داخل گفتگو باز می‌شود.';
          connBtn.style.display = 'none'; discBtn.style.display = '';
        } else {
          stEl.textContent = 'ربات متصل نیست.';
          connBtn.style.display = ''; discBtn.style.display = 'none';
        }
      };
      paintTg();
      connBtn.addEventListener('click', async () => {
        const token = ($('#se-tg-token') || {}).value || '';
        const admin_id = ($('#se-tg-admin') || {}).value || '';
        if (!token.trim() || !admin_id.trim()) return toast('توکن ربات و شناسه تلگرام را وارد کنید', 'err');
        connBtn.disabled = true; connBtn.textContent = 'در حال اتصال…';
        try {
          const r = await api('telegram', { token: token.trim(), admin_id: admin_id.trim() });
          toast('ربات @' + (r.bot_username || '') + ' متصل شد ✓ حالا در تلگرام /start بزنید', 'ok');
          await stateLoop(); renderView('settings');
        } catch (ex) { toast(ex.message, 'err'); }
        connBtn.disabled = false; connBtn.textContent = 'اتصال ربات';
      });
      discBtn.addEventListener('click', async () => {
        if (!confirm('ربات تلگرام قطع شود؟')) return;
        try {
          await api('telegram', null, 'DELETE');
          toast('ربات قطع شد', 'ok');
          await stateLoop(); renderView('settings');
        } catch (ex) { toast(ex.message, 'err'); }
      });

      // ── FinalMask & Cipher Suites section (v3.6) ──
      // guard: when state hasn't arrived yet the view renders a placeholder —
      // re-binding happens automatically via viewStale once data lands.
      const fmOn = $('#se-fm-on'), opSel = $('#se-opprof'), fpSel = $('#se-fp'), cipherSel = $('#se-cipher');
      if (!fmOn || !opSel || !fpSel || !cipherSel) return;
      const fmBlock = $('#fm-block'), opNote = $('#se-opnote'), fragOn = $('#se-fragon'),
        cipherWrap = $('#se-cipher-wrap');
      const ops = (S.state && S.state.settings.operators) || {};
      const paintFm = () => {
        fmBlock.style.display = fmOn.checked ? '' : 'none';
        const prof = ops[opSel.value];
        opNote.textContent = prof ? (prof.note || '') : '';
      };
      const initCipherCustom = () => {
        cipherWrap.style.display = cipherSel.value === '__custom__' ? '' : 'none';
      };
      fmOn.addEventListener('change', paintFm);
      opSel.addEventListener('change', () => {
        const prof = ops[opSel.value];
        // switching operator → refill fragment presets + fingerprint + sensible frag default
        if (prof) {
          const fl = $('#se-fraglen'); if (fl) fl.value = prof.frag_lengths || fl.value;
          const fd = $('#se-fragdelay'); if (fd) fd.value = prof.frag_delays || fd.value;
          if (prof.fp) fpSel.value = prof.fp;
        }
        if (fragOn) fragOn.checked = opSel.value !== 'auto';
        paintFm();
      });
      cipherSel.addEventListener('change', initCipherCustom);
      paintFm(); initCipherCustom();

      $('#se-save').addEventListener('click', async () => {
        const protocols = {};
        $$('.se-proto').forEach(p => protocols[p.dataset.k] = p.checked);
        const profV = opSel.value;
        const profDefault = ops[profV];
        const cipherSelV = cipherSel.value;
        // explicit custom lengths only apply on the custom profile — otherwise keep the preset
        const tune = {
          enabled: fmOn.checked,
          profile: profV,
          fp: fpSel.value,
          alpn: $('#se-alpn').value,
          cipher_suites: cipherSelV === '__custom__' ? (($('#se-cipher-custom') || {}).value || '') : cipherSelV,
          frag_on: fragOn && fragOn.checked,
          frag_packets: $('#se-fragpackets').value,
          frag_lengths: profV === 'custom' ? (($('#se-fraglen') || {}).value || '') : (profDefault ? profDefault.frag_lengths : undefined),
          frag_delays: profV === 'custom' ? (($('#se-fragdelay') || {}).value || '') : (profDefault ? profDefault.frag_delays : undefined),
          frag_maxsplit: ($('#se-fragmaxsplit') || {}).value || '',
          noise_on: $('#se-noiseon') && $('#se-noiseon').checked,
          noise_rand: ($('#se-noiserand') || {}).value || '',
          noise_delay: ($('#se-noisedelay') || {}).value || '',
        };
        if (tune.frag_lengths === undefined) delete tune.frag_lengths;
        if (tune.frag_delays === undefined) delete tune.frag_delays;
        try {
          const payload = {
            user: $('#se-user').value, address: $('#se-address').value,
            reality_sni: $('#se-sni').value, cfg_fmt: $('#se-fmt').value,
            random_sni: $('#se-randsni').checked, protocols,
            tuning: tune,
          };
          if ($('#se-sni-ov') && $('#se-sni-ov').value.trim() !== '') payload.sni_override = $('#se-sni-ov').value.trim();
          if ($('#se-session')) payload.session_hours = +$('#se-session').value || 12;
          if ($('#se-pass') && $('#se-pass').value) payload.pass = $('#se-pass').value;
          await api('settings', payload);
          toast('تنظیمات ذخیره شد ✓', 'ok'); refreshAll();
        } catch (ex) { toast(ex.message, 'err'); }
      });
    },
    // v3.10: starts the 2s live poller while the view is open
    online() { startOnlineLoop(); },
  };

  // ─────────── v3.10: live online-users loop ───────────
  let onlTimer = null, onlDurTimer = null;
  function stopOnlineLoop() {
    if (onlTimer) { clearInterval(onlTimer); onlTimer = null; }
    if (onlDurTimer) { clearInterval(onlDurTimer); onlDurTimer = null; }
  }
  function startOnlineLoop() {
    stopOnlineLoop();
    pollOnline(); // immediate first paint
    onlTimer = setInterval(() => { if (!document.hidden && S.view === 'online') pollOnline(); }, 2000);
    // durations glide every second WITHOUT re-requesting anything
    onlDurTimer = setInterval(() => { if (S.view === 'online' && !document.hidden) tickOnlineDurs(); }, 1000);
  }
  async function pollOnline() {
    let d; try { d = await api('online'); } catch { return; }
    S.online = d;
    paintOnlineBadge(d.count || 0);
    if (S.view === 'online') paintOnline(d);
  }
  function paintOnlineBadge(n) {
    const sb = $('#sb-online-count');
    if (sb) { sb.textContent = n; sb.classList.toggle('none', !n); }
    const del = $('#st-users-delta');
    if (del) del.textContent = n ? n + ' آنلاین' : '';
  }
  function onlRow(o) {
    const idle = o.status === 'idle';
    return `<div class="tr onl-row">
      <span class="u-name"><i class="u-ava">${esc((o.name || '·')[0] || '·').toUpperCase()}</i><b>${esc(o.name)}</b></span>
      <span class="u-status on ${idle ? 'idle' : ''}"><i class="dot"></i>${idle ? 'بی‌تحرک' : 'در حال استفاده'}</span>
      <span class="onl-mono onl-dur" data-since="${o.since}">${fmtDur(o.dur_s)}</span>
      <span class="onl-mono">↓ ${fmtRate(o.down_bps)} · ↑ ${fmtRate(o.up_bps)}</span>
      <span class="onl-mono" style="color:#b9b9b9">↓${fmtGB(o.down)} · ↑${fmtGB(o.up)}</span>
    </div>`;
  }
  function offRow(e) {
    return `<div class="tr onl-row off">
      <span class="u-name"><i class="u-ava">${esc((e.name || '·')[0] || '·').toUpperCase()}</i><b>${esc(e.name)}</b></span>
      <span class="onl-mono">${fmtDur(e.dur_s)}</span>
      <span class="onl-mono"><b>${clockTime(e.offline_at)}</b> <small style="color:#8d8d8d">(${relTime(e.offline_at)})</small></span>
      <span class="onl-mono" style="color:#b9b9b9">${fmtGB((e.up || 0) + (e.down || 0))}</span>
    </div>`;
  }
  function paintOnline(d) {
    const pill = $('#onl-count'); if (!pill) return;
    const c = d.count || 0;
    pill.textContent = c ? c + ' کاربر' : 'هیچ‌کس';
    pill.classList.toggle('zero', !c);
    const onl = d.online || [], off = d.offline || [];
    const tbl = $('#onl-users');
    if (tbl) tbl.innerHTML = '<div class="tr th"><span>کاربر</span><span>وضعیت</span><span>مدت اتصال</span><span>سرعت لحظه‌ای</span><span>مصرف این نشست</span></div>' + onl.map(onlRow).join('');
    const emp = $('#onl-empty'); if (emp) emp.hidden = !!c;
    const ftbl = $('#off-users');
    if (ftbl) ftbl.innerHTML = '<div class="tr th"><span>کاربر</span><span>مدت استفاده</span><span>زمان آفلاین شدن</span><span>مصرف نشست</span></div>' + off.map(offRow).join('');
    const femp = $('#off-empty'); if (femp) femp.hidden = !!off.length;
  }
  function tickOnlineDurs() {
    $$('.onl-dur[data-since]').forEach(el => {
      el.textContent = fmtDur(Math.floor(Date.now() / 1000 - (+el.dataset.since)));
    });
  }

  // ─────────── sidebar / header wiring ───────────
  function initDash() {
    $$('#sb-nav button').forEach(b => b.addEventListener('click', () => {
      renderView(b.dataset.view);
      $('#sidebar').classList.remove('open');
      $('#sb-backdrop').classList.remove('show');
    }));
    $('#burger').addEventListener('click', () => {
      $('#sidebar').classList.toggle('open');
      $('#sb-backdrop').classList.toggle('show');
    });
    $('#sb-backdrop').addEventListener('click', () => {
      $('#sidebar').classList.remove('open');
      $('#sb-backdrop').classList.remove('show');
    });
    $('#hero-close').addEventListener('click', () => { $('#hero').style.display = 'none'; });
    $('#view-all').addEventListener('click', () => renderView('users'));
    $('#hd-avatar-wrap').addEventListener('click', pickAvatar);
    $('#hd-avatar-wrap').addEventListener('keydown', e => { if (e.key === 'Enter') pickAvatar(); });
    $('#theme-toggle').addEventListener('click', () => toast('حالت روشن در این نسخه فعال نیست — تم سینمایی تیره 🙂'));
    $('#bell').addEventListener('click', () => toast(S.stats && S.stats.online_users ? S.stats.online_users + ' کاربر در همین لحظه در حال استفاده است' : 'در این لحظه کاربر آنلاینی نیست'));
    $('#tg-dl').addEventListener('change', e => S.fx.wave && S.fx.wave.set('rx', e.target.checked));
    $('#tg-ul').addEventListener('change', e => S.fx.wave && S.fx.wave.set('tx', e.target.checked));
    // v3.6 FIX: the دانلود/آپلود radios in the globe section were wired to an
    // EMPTY handler — a visible control that did nothing. They now filter the
    // live chart to the selected direction (chart checkboxes stay in sync).
    $$('#globe-tog input').forEach(r => r.addEventListener('change', () => {
      if (!r.checked || !S.fx.wave) return;
      const rx = r.value === 'rx';
      S.fx.wave.set('rx', rx); S.fx.wave.set('tx', !rx);
      const dl = $('#tg-dl'), ul = $('#tg-ul');
      if (dl) dl.checked = rx;
      if (ul) ul.checked = !rx;
    }));
    let searchT; // v3.6: debounce — re-rendering the users view on EVERY keystroke was janky
    $('#search').addEventListener('input', e => {
      clearTimeout(searchT);
      const q = e.target.value.trim().toLowerCase();
      if (!q || !S.state) return;
      searchT = setTimeout(() => {
        const hit = S.state.clients.find(c => c.name.toLowerCase().includes(q));
        if (hit) { renderView('users'); }
      }, 300);
    });
    // live FPS display (real)
    FX.onFps = f => {
      const a = $('#fps-chip'), b = $('#si-fps');
      if (a) a.textContent = f;
      if (b) b.textContent = f + ' fps';
    };
  }

  // ─────────── operator auto-detect (real) ───────────
  async function detectOperator() {
    try {
      const w = await api('whoami');
      S.whoami = w;
      applyGlobeNodes();
      if (w.operator && w.operator !== 'auto') {
        const strip = $('#op-strip');
        strip.hidden = false;
        $('#op-strip-text').textContent = 'اپراتور شما شناسایی شد: ' + (w.label || w.operator) + ' — اعمال تنظیمات بهینه (فرگمنت مناسب DPI این اپراتور) روی همه کانفیگ‌ها؟';
        $('#op-apply').addEventListener('click', async () => {
          try {
            await api('settings', { tuning: { enabled: true, profile: w.operator, frag_on: true } });
            toast('تنظیمات ' + (w.label || w.operator) + ' اعمال شد ✓', 'ok');
            strip.hidden = true;
          } catch (ex) { toast(ex.message, 'err'); }
        }, { once: true });
      }
    } catch { }
  }

  // ─────────── loops ───────────
  function stopTimers() { S.timers.forEach(clearInterval); S.timers = []; }
  function startLoops() {
    stopTimers();
    statLoop(); stateLoop(); pingLoop();
    // FIX(v3.3): gentler polling — 2s full-stats + 5s pings over a filtered
    // Iranian mobile link made the whole panel feel laggy; also everything
    // pauses while the tab is hidden (bandwidth + battery).
    // v3.6: 1s polling — matches the server's 1s sampler tick exactly, so the
    // 60fps chart engine receives a fresh sample every second and interpolates
    // in between (payload is gzipped, ~1.5KB/s). Stats view refreshes in place
    // via paintStats (sv-* ids) — no more full re-render every 5s.
    S.timers.push(setInterval(() => { if (!document.hidden) statLoop(); }, 1000));
    S.timers.push(setInterval(() => { if (!document.hidden) pingLoop(); }, 6000));
    S.timers.push(setInterval(() => { if (!document.hidden) stateLoop(); }, 45000));
  }
  async function refreshAll() { await stateLoop(); if (S.view === 'online') { startOnlineLoop(); return; } if (S.view !== 'dashboard') renderView(S.view); }

  // ─────────── boot ───────────
  async function boot() {
    initLogin();
    initDash();
    tgInit();
    // Telegram Mini App: one-tap login via signed initData (bot must be
    // connected in Settings and the Telegram user id must match the admin id).
    const tg = tgEnv();
    if (tg && tg.initData) {
      try {
        await api('login', { tg_init_data: tg.initData });
        toast('ورود با تلگرام ✓', 'ok');
        showDash();
        return;
      } catch (ex) { /* fall through — normal login flow */ }
    }
    try {
      await api('ping');
      showDash(); // showDash() itself starts loops + detectOperator
    } catch {
      showLogin();
    }
  }
  document.addEventListener('DOMContentLoaded', boot);
})();
