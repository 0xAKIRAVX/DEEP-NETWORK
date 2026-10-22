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
  function fmtGB(b) { return (b / 1073741824).toFixed(1) + ' GB'; }
  function fmtMBs(bps) { return (bps / 1048576).toFixed(1); }
  function fmtUptime(s) {
    if (s < 60) return s + ' ثانیه';
    if (s < 3600) return Math.floor(s / 60) + ' دقیقه';
    if (s < 86400) return Math.floor(s / 3600) + ' ساعت';
    return Math.floor(s / 86400) + ' روز';
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
        location.href = '/panel/api/client/' + main.id + '?profile=fast';
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
        ۴) اگر اتصال برقرار نشد، از «اسکنر IP» لبه نزدیک CDN را پیدا و در تنظیمات کانفیگ اعمال کنید.</p>`);
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
  async function pingLoop() {
    const t0 = performance.now();
    try { await api('ping'); } catch { return; }
    const ms = Math.round(performance.now() - t0);
    pingHist.push(ms); if (pingHist.length > 8) pingHist.shift();
    const med = pingHist.slice().sort((a, b) => a - b)[Math.floor(pingHist.length / 2)];
    const el = $('#g-ping'); if (el) el.textContent = med + ' ms';
    const st = $('#g-status');
    if (st) st.textContent = med < 130 ? 'عالی' : med < 280 ? 'خوب' : 'متوسط';
    FX.data.ping = med;
  }

  function paintStats(st) {
    FX.data.hist = st.hist.rx.map((v, i) => ({ t: (st.t || 0) - (st.hist.rx.length - 1 - i), rx: v, tx: st.hist.tx[i] }));
    FX.data.rx = st.rx; FX.data.tx = st.tx;
    const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
    set('#g-dl', fmtMBs(st.rx));
    set('#g-ul', fmtMBs(st.tx));
    set('#g-dl-tot', '(' + fmtGB(st.rx_total || 0) + ')');
    set('#g-ul-tot', '(' + fmtGB(st.tx_total || 0) + ')');
    set('#r-up', fmtMBs(st.tx));
    set('#r-down', fmtMBs(st.rx));
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
    ring('cpu', st.cpu || 0);
    ring('ram', st.mem || 0);
    ring('disk', st.disk.percent || 0);
    applyGlobeNodes();
  }
  function ring(name, pct) {
    const el = $('.ring[data-ring="' + name + '"]'); if (!el) return;
    $('b', el).textContent = Math.round(pct) + '%';
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
    // traffic + users delta
    let up = 0, down = 0;
    for (const c of st.clients) { up += c.up || 0; down += c.down || 0; }
    const tEl = $('#st-traffic'); if (tEl) tEl.textContent = fmtGB(up + down);
    const active = st.clients.filter(c => c.status === 'active').length;
    const dEl = $('#st-users-delta');
    if (dEl) dEl.textContent = '+' + (S.lastActive >= 0 && S.lastActive < active ? active - S.lastActive : 0);
    S.lastActive = active;
    // users table (top 5)
    const tbl = $('#users-table');
    if (tbl) {
      $$('.tr:not(.th)', tbl).forEach(r => r.remove());
      for (const c of st.clients.slice(0, 5)) {
        const row = document.createElement('div');
        row.className = 'tr';
        row.innerHTML = `<span class="u-name"><i class="u-ava">${esc(c.name[0] || '·').toUpperCase()}</i><b>${esc(c.name)}</b></span>
          <span class="u-status ${c.status !== 'active' ? c.status : ''}"><i class="dot"></i>${c.status === 'active' ? 'فعال' : c.status === 'quota' ? 'پایان حجم' : 'منقضی'}</span>
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
          <span class="u-status ${c.status !== 'active' ? c.status : ''}"><i class="dot"></i>${c.status === 'active' ? 'فعال' : c.status === 'quota' ? 'پایان حجم' : 'منقضی'}</span>
          <span class="u-use">${fmtGB((c.up || 0) + (c.down || 0))}</span>
          <span class="u-act">
            <button title="لینک اشتراک" data-act="sub"><svg viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 1 0-5.7-5.7l-1.2 1.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3A4 4 0 0 0 11 18.7l1.2-1.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg></button>
            <button title="ویرایش" data-act="edit"><svg viewBox="0 0 24 24"><path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg></button>
            <button title="حذف" data-act="del" ${c.main ? 'disabled style="opacity:.3"' : ''}><svg viewBox="0 0 24 24"><path d="M5 7h14M10 7V5h4v2m-7 0 1 13h8l1-13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
          </span></div>`).join('')}
      </div></section>`;
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
      ${st.clients.map(c => `<div style="display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px dashed rgba(255,255,255,.08)">
        <i class="u-ava">${esc(c.name[0] || '·').toUpperCase()}</i>
        <div style="flex:1;min-width:0"><b style="font-size:13px">${esc(c.name)}</b>
        <div class="linkbox" style="margin-top:5px"><span style="flex:1">${esc(c.sub_url)}</span>
        <button data-copy="${esc(c.sub_url)}" title="کپی"><svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" fill="none" stroke="currentColor" stroke-width="1.6"/></svg></button>
        <button data-qr="${esc(c.sub_url)}" title="QR"><svg viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M14 14h2v2h-2zm4 0h2v2h-2zm-4 4h2v2h-2zm4 0h2v2h-2z" fill="currentColor"/></svg></button></div></div></div>`).join('')}
      </section>`;
    },
    scanner() {
      return `<section class="info-sec" style="margin-top:20px">
      <h3>اسکنر IP — یافتن نزدیک‌ترین لبه CDN</h3>
      <p style="font-size:12px;color:#9d9d9d;margin:6px 0 14px;line-height:2">پینگ لبه‌های bunny.net (CDN خود Lucity) از <b>مرورگر خودتان</b> سنجیده می‌شود تا دقیقاً مطابق مسیر اینترنت شما باشد. لبه‌های نزدیک ایران (ترکیه، قفقاز، عراق، اروپا) اولویت دارند. روی «اعمال» بزنید تا همه کانفیگ‌ها از آن IP سرو شوند؛ برای برگشت، در «تنظیمات ← آدرس» مقدار را خالی کنید.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn primary" id="scan-bunny">اسکن لبه‌های CDN</button>
        <button class="btn" id="scan-custom">اسکن IP های دلخواه</button>
        <button class="btn" id="scan-stop" hidden>توقف اسکن</button>
      </div>
      <div class="progress" hidden id="scan-prog"><i></i></div>
      <p id="scan-status" style="font-size:11.5px;color:#8d8d8d;margin:8px 0 0;line-height:1.9"></p>
      <div class="scan-list" id="scan-out"></div>
      </section>`;
    },
    stats() {
      const st = S.stats || {};
      return `<section class="info-sec" style="margin-top:20px">
      <h3>آمار زنده سرور</h3>
      <ul class="kv">
      <li><span>پردازنده</span><b>${esc(st.cpu_model || '—')}</b></li>
      <li><span>مصرف CPU</span><b>${(st.cpu || 0).toFixed(1)}%</b></li>
      <li><span>حافظه</span><b>${(st.mem_total || 0) >= 1024 ? ((st.mem_used || 0) / 1024).toFixed(1) + ' / ' + ((st.mem_total || 0) / 1024).toFixed(1) + ' GB' : (st.mem_used || 0) + ' / ' + (st.mem_total || 0) + ' MB'} (${(Number(st.mem) || 0).toFixed(1)}%)</b></li>
      <li><span>دیسک</span><b>${(st.disk && st.disk.used || 0)} / ${(st.disk && st.disk.total || 0)} GB</b></li>
      <li><span>دانلود کل</span><b>${fmtGB(st.rx_total || 0)}</b></li>
      <li><span>آپلود کل</span><b>${fmtGB(st.tx_total || 0)}</b></li>
      <li><span>ترافیک ۳۰ روز</span><b>${st.traffic30 && st.traffic30.bytes ? fmtGB(st.traffic30.bytes) : '—'}</b></li>
      <li><span>کانال‌های فعال</span><b>${st.online || 0}</b></li>
      <li><span>زمان روشن</span><b>${fmtUptime(st.uptime || 0)}</b></li>
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

      <h4 style="margin:18px 0 8px;font-size:12.5px;color:#cfcfcf">بهینه‌سازی اپراتور (ضد فیلتر)</h4>
      <p style="font-size:11px;color:#8d8d8d;margin-bottom:10px;line-height:1.9">پروفایل اپراتور خودتان را انتخاب کنید تا فرگمنت TLS و اثر انگشت مرورگر روی همه کانفیگ‌ها اعمال شود. «خودکار» بدون فرگمنت کم‌ترین پینگ را دارد (SNI تصادفی خودش فیلتر SNI را دور می‌زند).</p>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px">
      ${Object.entries(ops).map(([k, o]) => `<label style="display:flex;flex-direction:column;gap:3px;font-size:11.5px;color:#c9c9c9;background:rgba(255,255,255,.025);border:1px solid var(--line);border-radius:10px;padding:10px 12px;cursor:pointer">
        <span style="display:flex;gap:8px;align-items:center"><input type="radio" name="opprof" value="${k}" ${k === (t.profile || 'auto') ? 'checked' : ''}><b>${esc(o.label)}</b></span>
        <small style="color:#7d7d7d;font-size:10px;line-height:1.7">${esc(o.note || '')}</small></label>`).join('')}
      </div>
      <div class="row2" style="margin-top:12px">
      <label class="field"><input id="se-fraglen" value="${esc(t.frag_lengths || '100-200')}" placeholder="طول فرگمنت (مثلاً 40-100)"></label>
      <label class="field"><input id="se-fragdelay" value="${esc(t.frag_delays || '10-20')}" placeholder="تأخیر فرگمنت به میلی‌ثانیه (مثلاً 10-20)"></label>
      </div>
      <label style="display:flex;gap:9px;align-items:center;font-size:12px;color:#c9c9c9;margin:8px 2px"><input type="checkbox" id="se-fragon" ${t.frag_on ? 'checked' : ''}><span class="cbx"></span>فرگمنت TLS فعال (با پروفایل «اختصاصی» مقادیر بالا اعمال می‌شود)</label>
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
          <p style="font-size:11px;color:#8d8d8d">در v2rayNG: Import from clipboard — در Hiddify: + و سپس Paste</p>`);
          $('#m-copy').addEventListener('click', () => copy(c.sub_url));
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
      const out = $('#scan-out'), prog = $('#scan-prog'), statusEl = $('#scan-status'), stopBtn = $('#scan-stop');
      let stopped = false;
      stopBtn.addEventListener('click', () => { stopped = true; });

      // hard-timeout fetch (works on every browser — no AbortSignal.timeout dependency)
      const timedFetch = (url, ms) => new Promise(resolve => {
        let ctl;
        try { ctl = new AbortController(); } catch { resolve(); return; }
        const t = setTimeout(() => { try { ctl.abort(); } catch { } }, ms);
        fetch(url, { mode: 'no-cors', cache: 'no-store', signal: ctl.signal })
          .catch(() => { })
          .finally(() => { clearTimeout(t); resolve(); });
      });

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
        statusEl.textContent = 'در حال دریافت لبه‌های تأییدشده… (اولین اسکن ممکن است تا ۳۰ ثانیه طول بکشد؛ دفعات بعد سریع است)';
        out.innerHTML = '';
        try {
          const r = await api('bunnyedges', {});
          if (!r.edges || !r.edges.length) {
            statusEl.textContent = '';
            out.innerHTML = '<p style="color:#f8b4b4;font-size:12px">لبه‌ای تأیید نشد — DOMAIN را چک کنید.</p>';
            return;
          }
          const TIMEOUT = 3500, CONC = 6; // capped parallelism — 40 hanging fetches used to saturate mobile links
          const edges = r.edges.slice(0, 60);
          // FIX(v3.3): `rows` was declared inside the try-block while renderRows
          // was declared outside → ReferenceError "rows is not defined" and the
          // scanner did NOTHING. Both now share one scope, and re-renders are
          // single-listener (event delegation), sorted as results arrive.
          const rows = edges.map(ip => ({ ip, geo: (r.geo || {})[ip] || null, ms: null }));
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
              const t0 = performance.now();
              await timedFetch('https://' + ip + '/', TIMEOUT);
              const ms = Math.round(performance.now() - t0);
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
        <label class="field"><textarea id="sc-list" rows="4" style="width:100%;background:none;border:0;outline:0;color:#eee;font-family:var(--mono);font-size:11px" placeholder="1.2.3.4&#10;5.6.7.8"></textarea>
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

      // operator radio → sensible frag_on default (auto = off, others = on)
      $$('input[name="opprof"]').forEach(rd => rd.addEventListener('change', () => {
        const cb = $('#se-fragon');
        if (cb) cb.checked = rd.value !== 'auto';
      }));
      $('#se-save').addEventListener('click', async () => {
        const protocols = {};
        $$('.se-proto').forEach(p => protocols[p.dataset.k] = p.checked);
        const prof = $('input[name="opprof"]:checked');
        const profV = prof ? prof.value : 'auto';
        const fragLen = ($('#se-fraglen') || {}).value || '';
        const profDefault = (S.state && S.state.settings.operators || {})[profV];
        // explicit custom lengths only apply on the custom profile — otherwise keep the preset
        const tune = {
          enabled: true, profile: profV,
          frag_on: $('#se-fragon') && $('#se-fragon').checked,
          frag_lengths: profV === 'custom' ? fragLen : (profDefault ? profDefault.frag_lengths : undefined),
          frag_delays: profV === 'custom' ? (($('#se-fragdelay') || {}).value || '') : (profDefault ? profDefault.frag_delays : undefined),
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
  };

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
    $('#bell').addEventListener('click', () => toast(S.stats && S.stats.online ? S.stats.online + ' تونل فعال است' : 'اعلان جدیدی نیست'));
    $('#tg-dl').addEventListener('change', e => S.fx.wave && S.fx.wave.set('rx', e.target.checked));
    $('#tg-ul').addEventListener('change', e => S.fx.wave && S.fx.wave.set('tx', e.target.checked));
    $$('#globe-tog input').forEach(r => r.addEventListener('change', () => { }));
    $('#search').addEventListener('input', e => {
      const q = e.target.value.trim().toLowerCase();
      if (!q || !S.state) return;
      const hit = S.state.clients.find(c => c.name.toLowerCase().includes(q));
      if (hit) { renderView('users'); }
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
    S.timers.push(setInterval(() => { if (!document.hidden) statLoop(); }, 3000));
    S.timers.push(setInterval(() => { if (!document.hidden) pingLoop(); }, 6000));
    S.timers.push(setInterval(() => { if (!document.hidden) stateLoop(); }, 45000));
    S.timers.push(setInterval(() => { if (S.view === 'stats' && !document.hidden) renderView('stats'); }, 5000));
  }
  async function refreshAll() { await stateLoop(); if (S.view !== 'dashboard') renderView(S.view); }

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
