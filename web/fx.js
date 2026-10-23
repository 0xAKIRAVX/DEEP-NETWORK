/* ═══════════════════════════════════════════════════════════
   DEEP NETWORK — FX engine (canvas: stars / globe / wave / spark)
   One rAF loop per active canvas · DPR cap · adaptive quality
   · ResizeObserver-cached sizes (no per-frame layout reads)
   · pause()/resume() so hidden canvases cost ZERO cpu
   All visuals driven by REAL data pushed via FX.data.*
   ═══════════════════════════════════════════════════════════ */
'use strict';
(function () {
  const FX = {
    fps: 0, _fpsAcc: 0, _fpsN: 0, _lowStreak: 0, _hiStreak: 0,
    quality: 1, dpr: Math.min(window.devicePixelRatio || 1, 2),
    data: { rx: 0, tx: 0, hist: [], ping: null, status: 'عالی', serverGeo: null, userGeo: null },
    onFps: null,
  };
  window.FX = FX;

  // ─────────── low-end device detection (v3.3) ───────────
  // Cheap phones (≤4 cores / ≤4GB) start degrading immediately instead of
  // waiting 3+ seconds of measured low FPS — the panel must feel smooth from
  // the very first frame.
  {
    const cores = navigator.hardwareConcurrency || 8;
    const mem = navigator.deviceMemory || 8;
    if (cores <= 4 || mem <= 4) {
      FX.quality = .6;
      FX.dpr = Math.min(FX.dpr, 1.25);
      try { document.body.setAttribute('data-fx', 'low'); } catch { }
    }
  }

  // ─────────── helpers ───────────
  const $ = (s) => document.querySelector(s);
  const clamp = (v, a, b) => v < a ? a : v > b ? b : v;

  // ─────────── canvas sizing: measure ONCE via ResizeObserver ───────────
  // getBoundingClientRect() per frame × 6 canvases × 60fps was forcing
  // hundreds of layout recalcs per second → the "panel lag" root cause #1.
  const cvDims = new WeakMap();
  const RO = window.ResizeObserver ? new ResizeObserver(entries => {
    for (const e of entries) {
      const cv = e.target, r = e.contentRect;
      let d = cvDims.get(cv); if (!d) { d = {}; cvDims.set(cv, d); }
      d.w = Math.max(1, Math.round(r.width)); d.h = Math.max(1, Math.round(r.height));
    }
  }) : null;

  function ctx2d(cv) {
    if (RO && !cvDims.has(cv)) { cvDims.set(cv, {}); RO.observe(cv); }
    let d = cvDims.get(cv);
    if (!d || !d.w) { // RO hasn't fired yet → one-time sync measure
      const r = cv.getBoundingClientRect();
      d = { w: Math.max(1, Math.round(r.width)), h: Math.max(1, Math.round(r.height)) };
      cvDims.set(cv, d);
    }
    const dpr = FX.dpr;
    if (cv.width !== d.w * dpr || cv.height !== d.h * dpr) { cv.width = d.w * dpr; cv.height = d.h * dpr; }
    const c = cv.getContext('2d');
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    return [c, d.w, d.h];
  }

  // ─────────── shared rAF loop with pause/resume ───────────
  // (hidden canvases used to keep burning CPU — pause() actually stops the loop)
  FX._loops = []; // debug registry: {name, isRunning}
  function makeLoop(frameFn, name) {
    let looping = false, running = true;
    function tick(t) {
      if (!running) { looping = false; return; }
      requestAnimationFrame(tick);
      frameFn(t);
    }
    const inst = {
      start() { running = true; if (!looping) { looping = true; requestAnimationFrame(tick); } },
      pause() { running = false; },
      resume() { running = true; if (!looping) { looping = true; requestAnimationFrame(tick); } },
      stop() { running = false; },
    };
    FX._loops.push({ name: name || 'anon', isRunning: () => running });
    return inst;
  }

  // ─────────── coarse land mask (72×36, 5°/cell) — recognizable Earth ───────────
  const LAND = (() => {
    const rows = [
      "........................########...................####............",
      "............############....#########..........###########........",
      ".....######.##############..#########...####..##################..",
      "....########.#############...########....####.###################.",
      "....########.#############.............####..###################.",
      "........###################.##...################################.",
      "........####################..##################################.",
      ".........##################...#################################.",
      "..........#############....###########....####...##############.",
      "..........###########.....############..########.####.#########.",
      "...........###########....#############..##########..#######...",
      ".............##########...##############..####.#####.########...",
      "...............########...################.####.######.####.....",
      "..................######...####################.#####.#####.....",
      "..................######.###############...##..#####.#####.......",
      "....................######..###############...######.#####......",
      ".....................########.############....###########.......",
      ".....................#########.##########.....###########.......",
      "......................##########.#######.#####.########.####......",
      "......................###########.######.######.##########.##...",
      ".......................##########.######.#####.##############...",
      ".......................##########.######..#####.###############..",
      "........................########..#####..#####.###############..",
      "........................#########.#####..####..##############...",
      ".......................#########.######.......###########.......",
      ".......................#########........................##..#...",
      ".......................########..............................##..",
      ".......................#######....................................",
      ".......................######.....................................",
      ".......................#####......................................",
      ".......................###........................................",
      ".......................#.........................................",
      "................................................................",
      "................................................................",
      "................................................................",
      "................................................................",
      "................................................................",
    ];
    // columns map: col0 = -180°, 5° each; rows: row0 = +90°, 5° each
    const grid = rows.map(r => r.split('').map(ch => ch === '#'));
    return (lat, lon) => {
      const row = clamp(Math.floor((90 - lat) / 5), 0, 35);
      const col = clamp(Math.floor((lon + 180) / 5), 0, 71);
      return grid[row][col];
    };
  })();

  // ─────────── star field (login + dashboard backgrounds) ───────────
  // NOTE: FPS is measured ONLY by fpsLoop below — animations must not
  // accumulate into FX._fpsAcc themselves.
  const starfields = [];
  function starField(canvas, opts) {
    if (!canvas) return { remake() { }, stop() { }, pause() { }, resume() { } };
    const o = Object.assign({ stars: 150, drift: 6, shoots: true }, opts);
    let stars = [], shoots = [];
    function make(n) {
      stars = [];
      for (let i = 0; i < n; i++) stars.push({
        x: Math.random(), y: Math.random(), r: Math.random() * 1.25 + .25,
        p: Math.random() * Math.PI * 2, s: .5 + Math.random() * 1.6,
        v: (Math.random() * .35 + .05) * (Math.random() < .5 ? -1 : 1),
      });
    }
    make(Math.round(o.stars * FX.quality));
    let last = performance.now();
    const loop = makeLoop(function frame(t) {
      if (FX.paused) return; // tab hidden → save battery
      const dt = Math.min(50, t - last) / 1000; last = t;
      const [c, w, h] = ctx2d(canvas);
      c.clearRect(0, 0, w, h);
      // stars — two size buckets to keep draw calls low
      for (const s of stars) {
        s.x += s.v * o.drift * dt / w;
        if (s.x > 1.02) s.x = -.02; if (s.x < -.02) s.x = 1.02;
        const tw = .35 + .65 * (.5 + .5 * Math.sin(t / 1000 * s.s + s.p));
        c.globalAlpha = tw * .85;
        c.fillStyle = '#fff';
        c.beginPath(); c.arc(s.x * w, s.y * h, s.r * (0.8 + tw * .4), 0, 6.283); c.fill();
      }
      // shooting particles
      if (o.shoots && FX.quality > .5) {
        if (Math.random() < dt * .14) shoots.push({ x: Math.random() * w * .7 + w * .15, y: Math.random() * h * .35, vx: (Math.random() * 300 + 250), vy: (Math.random() * 90 + 40), life: 1 });
        for (let i = shoots.length - 1; i >= 0; i--) {
          const p = shoots[i]; p.x += p.vx * dt; p.y += p.vy * dt; p.life -= dt * .8;
          if (p.life <= 0) { shoots.splice(i, 1); continue; }
          const g = c.createLinearGradient(p.x, p.y, p.x - p.vx * .12, p.y - p.vy * .12);
          g.addColorStop(0, `rgba(255,255,255,${.9 * p.life})`); g.addColorStop(1, 'transparent');
          c.strokeStyle = g; c.lineWidth = 1.4;
          c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x - p.vx * .12, p.y - p.vy * .12); c.stroke();
        }
      }
      c.globalAlpha = 1;
    });
    loop.start();
    const inst = {
      remake() { make(Math.round(o.stars * FX.quality)); },
      stop() { loop.stop(); },
      pause() { loop.pause(); },
      resume() { loop.resume(); },
    };
    starfields.push(inst);
    return inst;
  }
  // ─────────── globe (orthographic dot-earth, real rotation + real markers) ───────────
  function globe(canvasSel) {
    const cv = $(canvasSel);
    if (!cv) return { stop() { }, pause() { }, resume() { } };
    // fibonacci sphere points — fewer on small screens (phones)
    const N = Math.min(1500, window.innerWidth < 640 ? 650 : window.innerWidth < 960 ? 1000 : 1500);
    const pts = [];
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const th = i * 2.399963;
      const x = Math.cos(th) * r, z = Math.sin(th) * r;
      const lat = Math.asin(y) * 180 / Math.PI, lon = Math.atan2(z, x) * 180 / Math.PI;
      pts.push({ x, y, z, land: LAND(lat, lon) });
    }
    // arcs between real nodes
    let rot = -1.2, tilt = .35, spinV = .13, dragging = false, lastPX = 0, lastPY = 0, idleAt = 0;
    let markers = [], arcs = [];
    let skip = false; // low-quality half-rate
    // real network hub coordinates (world internet backbone)
    const HUBS = [
      { lat: 41.01, lon: 28.98 },  // Istanbul
      { lat: 50.11, lon: 8.68 },   // Frankfurt
      { lat: 52.37, lon: 4.9 },    // Amsterdam
      { lat: 25.2, lon: 55.27 },  // Dubai
    ];
    function setNodes(server, user) {
      markers = [];
      if (server) markers.push({ lat: server.lat, lon: server.lon, main: true, name: 'server' });
      if (user) markers.push({ lat: user.lat, lon: user.lon, main: false, name: 'user' });
      arcs = [];
      if (server) {
        for (const h of HUBS) arcs.push([server, h]);           // backbone arcs
        if (user) arcs.push([server, user]);                     // the admin's live route
        else arcs.push([{ lat: 35.7, lon: 51.4 }, server]);      // Tehran → server
      }
    }
    function proj(p, R, cx, cy) {
      // rotate around Y (rot) then X (tilt)
      const ca = Math.cos(rot), sa = Math.sin(rot);
      const x = p.x * ca - p.z * sa, z = p.x * sa + p.z * ca, y = p.y;
      const cb = Math.cos(tilt), sb = Math.sin(tilt);
      const y2 = y * cb - z * sb, z2 = y * sb + z * cb;
      return [cx + x * R, cy - y2 * R, z2];
    }
    const loop = makeLoop(function frame(t) {
      if (FX.paused) return;
      if (FX.quality < .7) { skip = !skip; if (skip) return; } // half-rate under sustained load
      const dt = Math.min(64, (t - (globe._lt || t)) / 1000); globe._lt = t;
      if (!dragging && t - idleAt > 2500) rot += spinV * dt; // frame-rate independent spin
      const [c, w, h] = ctx2d(cv);
      c.clearRect(0, 0, w, h);
      const cx = w / 2, cy = h / 2, R = Math.min(w, h) * .36;
      // atmosphere glow
      const g = c.createRadialGradient(cx, cy, R * .82, cx, cy, R * 1.22);
      g.addColorStop(0, 'rgba(255,255,255,.10)'); g.addColorStop(.5, 'rgba(255,255,255,.05)'); g.addColorStop(1, 'transparent');
      c.fillStyle = g; c.beginPath(); c.arc(cx, cy, R * 1.22, 0, 6.283); c.fill();
      // sphere base
      c.fillStyle = 'rgba(255,255,255,.018)';
      c.beginPath(); c.arc(cx, cy, R, 0, 6.283); c.fill();
      // graticule (lat/lon lines, faint)
      c.strokeStyle = 'rgba(255,255,255,.075)'; c.lineWidth = 1;
      for (let latI = -60; latI <= 60; latI += 20) {
        c.beginPath(); let started = false;
        for (let lon = -180; lon <= 180; lon += 5) {
          const la = latI * Math.PI / 180, lo = lon * Math.PI / 180;
          const [X, Y, Z] = proj({ x: Math.cos(la) * Math.cos(lo), y: Math.sin(la), z: Math.cos(la) * Math.sin(lo) }, R, cx, cy);
          if (Z > -.02) { started ? c.lineTo(X, Y) : c.moveTo(X, Y); started = true; } else started = false;
        }
        c.stroke();
      }
      for (let lonI = -180; lonI < 180; lonI += 20) {
        c.beginPath(); let started = false;
        for (let lat = -88; lat <= 88; lat += 5) {
          const la = lat * Math.PI / 180, lo = lonI * Math.PI / 180;
          const [X, Y, Z] = proj({ x: Math.cos(la) * Math.cos(lo), y: Math.sin(la), z: Math.cos(la) * Math.sin(lo) }, R, cx, cy);
          if (Z > -.02) { started ? c.lineTo(X, Y) : c.moveTo(X, Y); started = true; } else started = false;
        }
        c.stroke();
      }
      // dots (land bright, sea dim) — NO per-dot shadowBlur: it forced a
      // GPU blur per land point per frame → the "lag/freeze" root cause #2
      const step = FX.quality > .7 ? 1 : 2;
      for (let i = 0; i < pts.length; i += step) {
        const p = pts[i];
        const [X, Y, Z] = proj(p, R, cx, cy);
        if (Z < 0) continue;
        const depth = .35 + .65 * (Z + 1) / 2;
        if (p.land) {
          c.globalAlpha = depth * .95;
          c.fillStyle = Z > .25 ? '#fff' : '#c6c6c6';
          const sz = 1.5 + depth * 1.15;
          c.fillRect(X - sz / 2, Y - sz / 2, sz, sz);
        } else {
          c.globalAlpha = depth * .16;
          c.fillStyle = '#fff';
          c.fillRect(X - .5, Y - .5, 1, 1);
        }
      }
      c.globalAlpha = 1;
      // great-circle arcs (animated dash = live traffic feel)
      c.lineWidth = 1.3;
      for (const [a, b] of arcs) {
        const la1 = a.lat * Math.PI / 180, lo1 = a.lon * Math.PI / 180;
        const la2 = b.lat * Math.PI / 180, lo2 = b.lon * Math.PI / 180;
        const v1 = { x: Math.cos(la1) * Math.cos(lo1), y: Math.sin(la1), z: Math.cos(la1) * Math.sin(lo1) };
        const v2 = { x: Math.cos(la2) * Math.cos(lo2), y: Math.sin(la2), z: Math.cos(la2) * Math.sin(lo2) };
        c.strokeStyle = 'rgba(255,255,255,.55)';
        c.beginPath(); let started = false;
        for (let k = 0; k <= 48; k++) {
          const u = k / 48;
          let ix = v1.x + (v2.x - v1.x) * u, iy = v1.y + (v2.y - v1.y) * u, iz = v1.z + (v2.z - v1.z) * u;
          const n = Math.hypot(ix, iy, iz) || 1; ix /= n; iy /= n; iz /= n;
          const lift = 1 + Math.sin(u * Math.PI) * .16;
          const [X, Y, Z] = proj({ x: ix * lift, y: iy * lift, z: iz * lift }, R, cx, cy);
          if (Z > -.05) { started ? c.lineTo(X, Y) : c.moveTo(X, Y); started = true; } else started = false;
        }
        c.stroke();
        // moving pulse along arc
        const u = (t / 2600) % 1;
        let ix = v1.x + (v2.x - v1.x) * u, iy = v1.y + (v2.y - v1.y) * u, iz = v1.z + (v2.z - v1.z) * u;
        const n = Math.hypot(ix, iy, iz) || 1; ix /= n; iy /= n; iz /= n;
        const lift = 1 + Math.sin(u * Math.PI) * .16;
        const [X, Y, Z] = proj({ x: ix * lift, y: iy * lift, z: iz * lift }, R, cx, cy);
        if (Z > -.05) {
          c.fillStyle = '#fff'; c.shadowColor = '#fff'; c.shadowBlur = 9;
          c.beginPath(); c.arc(X, Y, 2.1, 0, 6.283); c.fill(); c.shadowBlur = 0;
        }
      }
      // markers
      for (const m of markers) {
        const la = m.lat * Math.PI / 180, lo = m.lon * Math.PI / 180;
        const [X, Y, Z] = proj({ x: Math.cos(la) * Math.cos(lo), y: Math.sin(la), z: Math.cos(la) * Math.sin(lo) }, R, cx, cy);
        if (Z < 0) continue;
        const pulse = 1 + .3 * Math.sin(t / 500);
        c.strokeStyle = m.main ? 'rgba(255,255,255,.9)' : 'rgba(255,255,255,.55)';
        c.lineWidth = 1.2;
        c.beginPath(); c.arc(X, Y, 6 * pulse, 0, 6.283); c.stroke();
        c.fillStyle = '#fff'; c.shadowColor = '#fff'; c.shadowBlur = 12;
        c.beginPath(); c.arc(X, Y, 2.6, 0, 6.283); c.fill(); c.shadowBlur = 0;
      }
    });
    loop.start();
    // drag interaction (real user control)
    cv.addEventListener('pointerdown', e => { dragging = true; lastPX = e.clientX; lastPY = e.clientY; try { cv.setPointerCapture(e.pointerId); } catch { } });
    cv.addEventListener('pointermove', e => {
      if (!dragging) return;
      rot += (e.clientX - lastPX) * .0065;
      tilt = clamp(tilt + (e.clientY - lastPY) * .005, -1.25, 1.25);
      lastPX = e.clientX; lastPY = e.clientY; idleAt = performance.now();
    });
    ['pointerup', 'pointercancel', 'pointerleave'].forEach(ev => cv.addEventListener(ev, () => { dragging = false; idleAt = performance.now(); }));
    FX.setGlobeNodes = setNodes;
    return {
      stop() { loop.stop(); },
      pause() { loop.pause(); },
      resume() { loop.resume(); },
    };
  }

  // ─────────── wave chart (live bandwidth — TRUE 60fps engine, v3.6) ───────────
  // v3.6 full rewrite. The old chart throttled redraws to ~10fps while fresh
  // data arrived only every 3s and was drawn with NO interpolation — the
  // polyline snapped to its new shape twice per second = "frame by frame
  // with lag". The new engine:
  //   · draws EVERY requestAnimationFrame (display rate: 60/90/120Hz)
  //   · time-anchored scroll: each point sits at its REAL timestamp and
  //     glides left continuously → fluid motion BETWEEN polls, never static
  //   · eased (exponential, dt-corrected) values + eased Y-scale → no
  //     snapping and no violent rescale when a burst spike lands
  //   · live head: the newest sample is extrapolated to "now" with the
  //     eased instantaneous rx/tx → the head always advances, always glows
  //   · wall-clock time ticks that scroll WITH the data (they never jump)
  //   · server→client clock offset auto-corrected each payload
  function wave(canvasSel) {
    const cv = $(canvasSel);
    if (!cv) return { set() { }, stop() { }, pause() { }, resume() { } };
    let show = { rx: true, tx: true };
    const WINDOW = 90;                 // seconds of history on screen
    let srcRef = null;                 // identity of last-ingested FX.data.hist
    let pts = [];                      // [{t, rx, tx, drx, dtx}] d*=eased display
    let dMax = 1;                       // eased Y scale
    let curRx = 0, curTx = 0, dCurRx = 0, dCurTx = 0;
    let off = 0;                        // server→client clock offset (seconds)
    let lastT = 0, lastDataT = 0;        // lastDataT = wall time of last NEW payload (snap detection)
    function ingest(nowMs) {
      curRx = +FX.data.rx || 0; curTx = +FX.data.tx || 0;
      const h = FX.data.hist;
      if (!h || h === srcRef) return;
      srcRef = h;
      // first paint, or frames kept running while data paused (>3.5s stale) → jump instantly
      const snap = !pts.length || (lastDataT > 0 && nowMs - lastDataT > 3500);
      const old = new Map(pts.map(p => [p.t, p]));
      const next = [];
      for (let i = 0; i < h.length; i++) {
        const prev = old.get(h[i].t);
        if (prev) {
          next.push({ t: h[i].t, rx: h[i].rx, tx: h[i].tx, drx: prev.drx, dtx: prev.dtx });
        } else {
          // continuity: a brand-new point starts at its neighbour's CURRENT
          // display value and eases to target — starting at 0 made the head
          // of the curve dip to baseline once per second (1Hz artifact).
          const base = next.length ? next[next.length - 1] : null;
          next.push({
            t: h[i].t, rx: h[i].rx, tx: h[i].tx,
            drx: base ? base.drx : (snap ? h[i].rx : 0),
            dtx: base ? base.dtx : (snap ? h[i].tx : 0),
          });
        }
      }
      pts = next;
      lastDataT = nowMs;
      const st = FX.data.serverT;
      if (st) off = nowMs / 1000 - st;
      if (snap) { dCurRx = curRx; dCurTx = curTx; }
    }
    const loop = makeLoop(function frame(t) {
      if (FX.paused) { lastT = t; return; }
      const dt = Math.min(64, (t - lastT) || 16) / 1000; lastT = t;
      if (FX.quality < .7 && ((t / 16) | 0) % 2) return; // half-rate only under sustained load
      ingest(t);
      const [c, w, h] = ctx2d(cv);
      c.clearRect(0, 0, w, h);
      const padL = 48, padR = 14, padT = 14, padB = 24;
      const iw = w - padL - padR, ih = h - padT - padB;
      const nowS = t / 1000 - off;          // server time mapped onto client clock
      const t0 = nowS - WINDOW;
      // ── eased values (dt-corrected exponential smoothing) ──
      const kV = 1 - Math.exp(-dt * 12);    // per-point catch-up: responsive yet smooth
      const kC = 1 - Math.exp(-dt * 7);     // live head value
      dCurRx += (curRx - dCurRx) * kC; dCurTx += (curTx - dCurTx) * kC;
      let tMax = 1;
      for (const p of pts) {
        if (p.t < t0 - 2) continue;
        if (show.rx && p.rx > tMax) tMax = p.rx;
        if (show.tx && p.tx > tMax) tMax = p.tx;
      }
      if (show.rx && dCurRx > tMax) tMax = dCurRx;
      if (show.tx && dCurTx > tMax) tMax = dCurTx;
      tMax *= 1.15;
      dMax += (tMax - dMax) * (1 - Math.exp(-dt * 3.2)); // gentle rescale = no flicker
      for (const p of pts) { p.drx += (p.rx - p.drx) * kV; p.dtx += (p.tx - p.dtx) * kV; }
      const X = tt => padL + iw * (tt - t0) / WINDOW;
      const Y = v => padT + ih * (1 - clamp(v / dMax, 0, 1));
      // ── grid + Y labels ──
      c.font = '10px ' + MONO; c.textBaseline = 'middle'; c.lineWidth = 1;
      c.lineJoin = 'round'; c.lineCap = 'round';
      c.strokeStyle = 'rgba(255,255,255,.06)'; c.fillStyle = '#7d7d7d';
      for (let i = 0; i <= 4; i++) {
        const y = padT + ih * i / 4;
        c.beginPath(); c.moveTo(padL, y); c.lineTo(w - padR, y); c.stroke();
        c.textAlign = 'left';
        c.fillText(fmtNum(dMax * (4 - i) / 4), 4, y);
      }
      // ── wall-clock ticks (scroll with the data — never jump) ──
      c.textAlign = 'center'; c.fillStyle = '#7d7d7d';
      let step = 60;
      for (const s of [5, 10, 15, 30]) { if (iw * s / WINDOW >= 56) { step = s; break; } }
      const firstTick = Math.ceil(t0 / step) * step;
      for (let tt = firstTick; tt <= nowS; tt += step) {
        const x = X(tt);
        c.strokeStyle = 'rgba(255,255,255,.045)';
        c.beginPath(); c.moveTo(x, padT); c.lineTo(x, padT + ih); c.stroke();
        const d = new Date(tt * 1000);
        c.fillText(String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') +
          (step < 30 ? ':' + String(d.getSeconds()).padStart(2, '0') : ''), x, h - 9);
      }
      // ── curves + live head ──
      const line = (key, dkey, color, fill) => {
        if (!show[key]) return;
        let started = false, px = 0, py = 0, sx = 0;
        c.beginPath();
        for (const p of pts) {
          if (p.t < t0) continue;
          const x = X(p.t), y = Y(p[dkey]);
          if (!started) { c.moveTo(x, y); started = true; px = x; py = y; sx = x; }
          else { c.quadraticCurveTo(px, py, (px + x) / 2, (py + y) / 2); px = x; py = y; }
        }
        if (!started) return;
        const hv = key === 'rx' ? dCurRx : dCurTx;
        const hx = X(nowS), hy = Y(hv);
        c.quadraticCurveTo(px, py, (px + hx) / 2, (py + hy) / 2);
        c.lineTo(hx, hy);
        c.strokeStyle = color; c.lineWidth = 2; c.stroke();
        if (fill) {
          c.lineTo(hx, padT + ih); c.lineTo(sx, padT + ih); c.closePath();
          const g = c.createLinearGradient(0, padT, 0, padT + ih);
          g.addColorStop(0, 'rgba(255,255,255,.17)'); g.addColorStop(1, 'rgba(255,255,255,0)');
          c.fillStyle = g; c.fill();
        }
        // head dot with glow (ONE shadow per frame — cheap, unlike the old per-dot blur)
        c.fillStyle = '#fff'; c.shadowColor = color; c.shadowBlur = 10;
        c.beginPath(); c.arc(hx, hy, 2.6 + .5 * Math.sin(t / 300), 0, 6.283); c.fill();
        c.shadowBlur = 0;
      };
      line('rx', 'drx', '#ffffff', true);
      line('tx', 'dtx', 'rgba(255,255,255,.45)', false);
      if (!pts.length) {
        c.fillStyle = 'rgba(255,255,255,.28)'; c.textAlign = 'center';
        c.font = '11px ' + MONO;
        c.fillText('در انتظار داده\u200cهای زنده…', padL + iw / 2, padT + ih / 2);
      }
    });
    loop.start();
    return {
      set(k, v) { show[k] = v; },
      stop() { loop.stop(); },
      pause() { loop.pause(); },
      resume() { loop.resume(); },
    };
  }

  function fmtNum(v) { // v is bytes/second
    if (v >= 1024 * 1024 * 1024) return (v / 1024 / 1024 / 1024).toFixed(1) + 'GB/s';
    if (v >= 1024 * 1024) return (v / 1024 / 1024).toFixed(1) + 'MB/s';
    if (v >= 1024) return (v / 1024).toFixed(1) + 'KB/s';
    return Math.max(0, Math.round(v)) + 'B/s';
  }

  // ─────────── sparkline (network card — same 60fps live engine) ───────────
  function spark(canvasSel) {
    const cv = $(canvasSel);
    if (!cv) return { stop() { }, pause() { }, resume() { } };
    const WINDOW = 45;                  // seconds on screen
    let srcRef = null, pts = [];
    let curRx = 0, curTx = 0, dCurRx = 0, dCurTx = 0;
    let dMax = 1, off = 0, lastT = 0, lastDataT = 0;
    function ingest(nowMs) {
      curRx = +FX.data.rx || 0; curTx = +FX.data.tx || 0;
      const h = FX.data.hist;
      if (!h || h === srcRef) return;
      srcRef = h;
      const snap = !pts.length || (lastDataT > 0 && nowMs - lastDataT > 3500);
      const old = new Map(pts.map(p => [p.t, p]));
      const next = [];
      for (let i = 0; i < h.length; i++) {
        const prev = old.get(h[i].t);
        if (prev) {
          next.push({ t: h[i].t, rx: h[i].rx, tx: h[i].tx, drx: prev.drx, dtx: prev.dtx });
        } else {
          const base = next.length ? next[next.length - 1] : null;
          next.push({
            t: h[i].t, rx: h[i].rx, tx: h[i].tx,
            drx: base ? base.drx : (snap ? h[i].rx : 0),
            dtx: base ? base.dtx : (snap ? h[i].tx : 0),
          });
        }
      }
      pts = next;
      lastDataT = nowMs;
      const st = FX.data.serverT;
      if (st) off = nowMs / 1000 - st;
      if (snap) { dCurRx = curRx; dCurTx = curTx; }
    }
    const loop = makeLoop(function frame(t) {
      if (FX.paused) { lastT = t; return; }
      const dt = Math.min(64, (t - lastT) || 16) / 1000; lastT = t;
      if (FX.quality < .7 && ((t / 16) | 0) % 2) return;
      ingest(t);
      const [c, w, h] = ctx2d(cv);
      c.clearRect(0, 0, w, h);
      const nowS = t / 1000 - off, t0 = nowS - WINDOW;
      const kV = 1 - Math.exp(-dt * 12), kC = 1 - Math.exp(-dt * 7);
      dCurRx += (curRx - dCurRx) * kC; dCurTx += (curTx - dCurTx) * kC;
      let tMax = 1;
      for (const p of pts) {
        if (p.t < t0 - 2) continue;
        if (p.rx > tMax) tMax = p.rx;
        if (p.tx > tMax) tMax = p.tx;
      }
      if (dCurRx > tMax) tMax = dCurRx;
      if (dCurTx > tMax) tMax = dCurTx;
      tMax *= 1.15;
      dMax += (tMax - dMax) * (1 - Math.exp(-dt * 3.2));
      for (const p of pts) { p.drx += (p.rx - p.drx) * kV; p.dtx += (p.tx - p.dtx) * kV; }
      const X = tt => w * (tt - t0) / WINDOW;
      const Y = v => h - 3 - (h - 8) * clamp(v / dMax, 0, 1);
      const line = (key, dkey, color, fill) => {
        let started = false, px = 0, py = 0, sx = 0;
        c.beginPath();
        for (const p of pts) {
          if (p.t < t0) continue;
          const x = X(p.t), y = Y(p[dkey]);
          if (!started) { c.moveTo(x, y); started = true; px = x; py = y; sx = x; }
          else { c.quadraticCurveTo(px, py, (px + x) / 2, (py + y) / 2); px = x; py = y; }
        }
        if (!started) return;
        const hv = key === 'rx' ? dCurRx : dCurTx;
        const hx = X(nowS), hy = Y(hv);
        c.quadraticCurveTo(px, py, (px + hx) / 2, (py + hy) / 2);
        c.lineTo(hx, hy);
        c.strokeStyle = color; c.lineWidth = 1.4; c.stroke();
        if (fill) {
          c.lineTo(hx, h); c.lineTo(sx, h); c.closePath();
          const g = c.createLinearGradient(0, 0, 0, h);
          g.addColorStop(0, 'rgba(255,255,255,.14)'); g.addColorStop(1, 'rgba(255,255,255,0)');
          c.fillStyle = g; c.fill();
        }
      };
      line('rx', 'drx', 'rgba(255,255,255,.9)', true);
      line('tx', 'dtx', 'rgba(255,255,255,.38)', false);
    });
    loop.start();
    return { // FIX: return was missing — spark could never be paused
      stop() { loop.stop(); },
      pause() { loop.pause(); },
      resume() { loop.resume(); },
    };
  }

  // mono font for canvas labels (matches --mono of the page)
  const MONO = (getComputedStyle(document.documentElement).getPropertyValue('--mono') || 'monospace').trim() || 'monospace';

  // ─────────── FPS manager (real measured FPS + adaptive quality) ───────────
  let fpsLoopLast = performance.now();
  function fpsLoop(t) {
    const dt = t - fpsLoopLast; fpsLoopLast = t;
    if (dt > 0 && dt < 500) { FX._fpsAcc += dt; FX._fpsN++; }
    if (FX._fpsAcc >= 1000) {
      FX.fps = Math.round(FX._fpsN * 1000 / FX._fpsAcc);
      FX._fpsAcc = 0; FX._fpsN = 0;
      if (FX.onFps) FX.onFps(FX.fps);
      // adaptive quality
      if (FX.fps < 42) { FX._lowStreak++; FX._hiStreak = 0; }
      else if (FX.fps > 55) { FX._hiStreak++; FX._lowStreak = 0; }
      else { FX._lowStreak = 0; FX._hiStreak = 0; }
      if (FX._lowStreak >= 3 && FX.quality > .5) {
        FX.quality = .5; FX.dpr = Math.min(FX.dpr, 1.25);
        document.body.setAttribute('data-fx', 'low');
        if (FX._remakeStars) FX._remakeStars();
      } else if (FX._hiStreak >= 20 && FX.quality < 1) {
        FX.quality = 1; FX.dpr = Math.min(window.devicePixelRatio || 1, 2);
        document.body.removeAttribute('data-fx');
        if (FX._remakeStars) FX._remakeStars();
      }
    }
    requestAnimationFrame(fpsLoop);
  }
  requestAnimationFrame(fpsLoop);

  // pause everything when tab hidden (saves battery → real best-effort FPS)
  document.addEventListener('visibilitychange', () => {
    FX.paused = document.hidden;
  });

  // ─────────── number tweens (values GLIDE instead of jumping, v3.6) ───────────
  // Driven by its own rAF loop, independent of chart loops, so it animates on
  // every view. Entries whose element left the DOM (view re-render) are GC'd.
  const tweens = new Map(); // el → {cur, target, fmt, last}
  let numLast = 0;
  function numLoop(t) {
    requestAnimationFrame(numLoop);
    const dt = Math.min(64, (t - numLast) || 16) / 1000; numLast = t;
    if (FX.paused) return;
    for (const [el, tw] of tweens) {
      if (!el.isConnected) { tweens.delete(el); continue; }
      tw.cur += (tw.target - tw.cur) * (1 - Math.exp(-dt * 6));
      const s = tw.fmt(tw.cur);
      if (s !== tw.last) { el.textContent = s; tw.last = s; } // write only when the text actually changes
    }
  }
  requestAnimationFrame(numLoop);
  FX.tweenNum = function (el, target, fmt) {
    if (!el) return;
    let tw = tweens.get(el);
    if (!tw) { tweens.set(el, { cur: target, target, fmt: fmt || String, last: '' }); return; }
    tw.target = target;
    if (fmt) tw.fmt = fmt;
  };

  // ─────────── public API ───────────
  FX.starField = starField;
  FX.globe = globe;
  FX.wave = wave;
  FX.spark = spark;
  FX._remakeStars = () => starfields.forEach(s => s.remake && s.remake());
})();
