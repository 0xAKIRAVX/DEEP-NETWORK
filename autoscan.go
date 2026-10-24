package main

// ─────────── v3.14: اسکن و جایگزاری خودکار / Auto edge scanner ───────────
// The panel itself scans, grades and APPLIES the best CDN edges into every
// user's configs — no button press needed:
//   * candidates: bunnyEdgesFor() returns VERIFIED, geo-balanced edges that
//     provably serve the panel domain, near-Iran regions first (the v3.3
//     lesson: ranking by server RTT alone would hand the win to German PoPs,
//     useless for Iranian users — the region order IS the ranking).
//   * per edge: 3 × TLS handshake (median = ping, spread = jitter, failures
//     = packet loss) + one real 64 KB download through edge→origin (speed).
//   * gate: ONLY loss == 0 edges are eligible (fallback: OK edges if every
//     probe lost a packet), then top-5 in region order, tie-broken by speed.
//   * apply: state.TopEdges + MultiEdge (subscription expansion) and — only
//     when the current address is empty / the domain / was set by a previous
//     auto-scan — state.Address = best edge. A manually chosen address is
//     never touched.
// Runs 90s after boot and then every 6h while enabled; can be triggered on
// demand via POST /panel/api/autoscan.

import (
        "fmt"
        "sort"
        "strings"
        "sync"
        "sync/atomic"
        "time"
)

const (
        autoScanTargets = 24 // probe head of the geo-balanced shortlist
        autoScanKeep    = 5
        autoScanMinKBps = 15 // edge must actually move bytes to qualify
)

// autoScanInterval is the scan cadence (admin-settable, default 1h per user
// request, clamped to [1, 24]).
func autoScanInterval() time.Duration {
        stateMu.RLock()
        h := state.AutoScanHours
        stateMu.RUnlock()
        if h < 1 {
                h = 1
        }
        if h > 24 {
                h = 24
        }
        return time.Duration(h) * time.Hour
}

var (
        autoScanMu      sync.Mutex // serializes scans
        autoScanRunning atomic.Bool
)

// autoScanDomain resolves the public panel domain to probe through the edges.
func autoScanDomain() string {
        if d := envStr("DOMAIN", ""); d != "" && !isIPLiteral(d) {
                return d
        }
        stateMu.RLock()
        defer stateMu.RUnlock()
        if ov := strings.TrimSpace(state.SNIOverride); ov != "" && !isIPLiteral(ov) {
                return ov
        }
        if h := strings.TrimSpace(state.LastHost); h != "" && !isIPLiteral(h) {
                return h
        }
        return ""
}

// probeEdge grades one edge: handshake ×3 (median/jitter/loss) + throughput.
func probeEdge(ip, domain string, geo map[string]map[string]string) EdgeScore {
        es := EdgeScore{IP: ip, TS: time.Now().Unix()}
        if g := geo[ip]; g != nil {
                es.CC = g["cc"]
                es.City = g["city"]
        }
        var hss []float64
        loss := 0
        for k := 0; k < 3; k++ {
                r := measureEdgeSpeed(ip, domain, 8, 5*time.Second)
                if !r.OK {
                        loss++
                        continue
                }
                hss = append(hss, r.HsMs)
        }
        if len(hss) == 0 {
                es.Loss = 100 // all probes failed — never eligible
                return es
        }
        if sp := measureEdgeSpeed(ip, domain, 64, 6*time.Second); sp.OK {
                es.SpeedKbps = sp.Kbps
        }
        sort.Float64s(hss)
        es.Med = round1(hss[len(hss)/2])
        es.Jit = round1(hss[len(hss)-1] - hss[0])
        es.Loss = float64(loss) / 3 * 100
        es.OriginMs = es.Med
        // display score: lower = better
        es.Score = round1(es.Med + 0.5*es.Jit + 8*es.Loss)
        return es
}

// ─────────── v3.19: edge blocklist (the admin's ground truth) ───────────
// The 6 Iranian probe nodes and every sandbox measurement can pass an edge
// that the ADMIN's own ISP still kills (measured live: Stockholm
// 195.181.166.158 and the bunny.net SNI front passed 6/6 probes while the
// user's v2rayNG reported -1). parseEdgeBlock accepts a JSON array or a
// comma/space separated string and keeps only valid IP literals.
func parseEdgeBlock(v any) []string {
        var raw []string
        switch x := v.(type) {
        case []any:
                for _, it := range x {
                        raw = append(raw, fmt.Sprintf("%v", it))
                }
        case string:
                raw = strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' })
        }
        seen := map[string]bool{}
        var out []string
        for _, s := range raw {
                s = strings.TrimSpace(strings.Trim(s, "[]"))
                if s == "" || seen[s] || !isIPLiteral(s) {
                        continue
                }
                seen[s] = true
                out = append(out, s)
        }
        return out
}

// edgeBlocked reports whether ip sits on the blocklist (NO lock taken —
// callers already hold stateMu or use edgeBlockedState).
func edgeBlockedLocked(ip string) bool {
        for _, b := range state.EdgeBlock {
                if b == ip {
                        return true
                }
        }
        return false
}

// edgeBlockedState is the lock-taking variant for code paths that hold no
// stateMu when they call (buildLinks edge loop, localDirectAddr).
func edgeBlockedState(ip string) bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return edgeBlockedLocked(ip)
}

// irProbeTLS is the per-edge TLS prober (var so tests can stub the network).
var irProbeTLS = irCheckEdgeTLS

// irGateEdges (v3.18.1): the subscription gate that ended the "-1 configs".
// An edge can look perfect from the panel's EU vantage (loss 0, 400 KB/s,
// TCP-reachable 6/6 from Iranian probe nodes) and still be TLS-dead from
// Iran — every regional PoP the users reported (🥈 Bucharest / E5 Karbala /
// EdgeUno-Istanbul / the panel's own 185.111.111.x geo answer) accepted the
// TCP SYN from all 6 IR nodes and timed out on the TLS ClientHello. This
// gate asks the IR nodes to do a REAL https://<ip>/ fetch. IRTLS verdicts
// (v3.18.1, normalized): 1 = at least one IR node completed TLS (ships),
// 0 = every node failed (dead — dropped), -1 = probe unavailable (kept,
// panel-side health stands). A legacy "2" (raw irCheckURL blocked verdict
// written by the first v3.18 build) is treated as dead via IRTLS != 1.
func irGateEdges(healthy []*EdgeScore, maxProbe int) []*EdgeScore {
        if len(healthy) == 0 {
                return healthy
        }
        cands := healthy
        if len(cands) > maxProbe {
                cands = cands[:maxProbe]
        }
        var wg sync.WaitGroup
        sem := make(chan struct{}, 3) // polite with the free check-host API
        for _, e := range cands {
                wg.Add(1)
                go func(e *EdgeScore) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()
                        if v := irProbeTLS(e.IP); v >= 0 {
                                e.IRTLS, e.IRTLSAt = v, time.Now().Unix()
                        }
                }(e)
        }
        wg.Wait()
        var verified, rest []*EdgeScore
        for _, e := range healthy {
                switch {
                case e.IRTLS == 1:
                        verified = append(verified, e)
                case e.IRTLSAt > 0 && e.IRTLS != 1:
                        // measured TLS-dead from Iran (0 or legacy 2) — never ships
                default:
                        rest = append(rest, e) // -1 = probe unavailable, or not yet probed this round
                }
        }
        return append(verified, rest...)
}

// applyAutoEdges is the pure state-transition of an auto-scan (unit-testable):
// returns the new primary address. A manually-set address survives untouched.
func applyAutoEdges(st *State, healthy []*EdgeScore, now time.Time) string {
        if len(healthy) == 0 {
                return st.Address
        }
        st.TopEdges = healthy
        st.MultiEdge = true
        st.AutoScanAt = now.Unix()
        best := healthy[0].IP
        cur := strings.TrimSpace(st.Address)
        // replaceable: empty, the domain form (CDN geo-DNS stays available as
        // the 🌐 DNS entry), a previous auto-scan choice, or the same best IP.
        // A manually pinned IP literal always survives.
        if cur == "" || cur == best || st.AutoAddr || !isIPLiteral(cur) {
                st.Address = best
                st.AutoAddr = true
        }
        return st.Address
}

// autoScanOnce runs one full scan+apply cycle.
func autoScanOnce() (bool, string) {
        if !autoScanMu.TryLock() {
                return false, "اسکن دیگری در حال اجراست"
        }
        defer autoScanMu.Unlock()
        autoScanRunning.Store(true)
        defer autoScanRunning.Store(false)

        domain := autoScanDomain()
        if domain == "" {
                return false, "دامنه عمومی پنل مشخص نیست"
        }
        edges, geo, _ := bunnyEdgesFor(domain, "4")
        if len(edges) == 0 {
                return false, "هیچ لبه تأییدشده‌ای پیدا نشد"
        }
        if len(edges) > autoScanTargets {
                edges = edges[:autoScanTargets]
        }

        results := make([]EdgeScore, len(edges))
        sem := make(chan struct{}, 8)
        var wg sync.WaitGroup
        for i, ip := range edges {
                wg.Add(1)
                go func(i int, ip string) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()
                        results[i] = probeEdge(ip, domain, geo)
                }(i, ip)
        }
        wg.Wait()

        var healthy []*EdgeScore
        for i := range results {
                if results[i].Loss == 0 && results[i].SpeedKbps >= autoScanMinKBps {
                        healthy = append(healthy, &results[i])
                }
        }
        if len(healthy) == 0 { // relax the speed gate before giving up
                for i := range results {
                        if results[i].Loss == 0 {
                                healthy = append(healthy, &results[i])
                        }
                }
        }
        if len(healthy) == 0 {
                return false, fmt.Sprintf("هیچ لبه سالمی (پکت‌لاست ۰) از %d لبه پیدا نشد", len(edges))
        }
        // v3.19: the admin's blocklist is ground truth — an edge the user
        // measured as -1 on their own ISP never rides the subscription again,
        // even when every probe node disagrees.
        {
                var keep []*EdgeScore
                for _, e := range healthy {
                        if !edgeBlockedState(e.IP) {
                                keep = append(keep, e)
                        }
                }
                healthy = keep
        }
        if len(healthy) == 0 {
                stateMu.Lock()
                state.TopEdges = nil
                state.MultiEdge = false
                state.AutoScanAt = time.Now().Unix()
                saveStateLocked()
                enabled := state.AutoScan
                stateMu.Unlock()
                go doctorRun()
                logf("auto-scan: every healthy edge is on the admin blocklist — shipping primary/DNS/🎭/🛡️ only")
                msg := "همه لبه‌های سالم در فهرست حذف شما هستند — کانفیگ‌ها فقط با مسیر اصلی، دامنه، 🎭 و 🛡️ مستقیم ساخته می‌شوند"
                if !enabled {
                        msg += " (اسکن خودکار خاموش است — فقط این بار اجرا شد)"
                }
                return true, msg
        }
        if len(healthy) > autoScanKeep {
                healthy = healthy[:autoScanKeep]
        }

        // v3.18: IR-TLS gate — an edge that cannot complete a TLS handshake
        // from Iranian vantage points is a guaranteed -1 for the users, no
        // matter how well it scores from the panel's EU vantage. Dead edges
        // never ride the subscription again.
        healthy = irGateEdges(healthy, 8)
        if len(healthy) == 0 {
                stateMu.Lock()
                state.TopEdges = nil
                state.MultiEdge = false
                state.AutoScanAt = time.Now().Unix()
                saveStateLocked()
                enabled := state.AutoScan
                stateMu.Unlock()
                go doctorRun()
                logf("auto-scan: all %d healthy edges are TLS-dead from Iran — shipping primary/DNS/🎭/🛡️ only", autoScanKeep)
                msg := "هیچ لبه‌ای از ایران قابل اتصال (TLS) نبود — کانفیگ‌ها فقط با مسیر اصلی، دامنه، 🎭 و 🛡️ مستقیم ساخته می‌شوند تا هیچ کانفیگ منفی یک ندهد"
                if !enabled {
                        msg += " (اسکن خودکار خاموش است — فقط این بار اجرا شد)"
                }
                return true, msg
        }

        stateMu.Lock()
        newAddr := applyAutoEdges(state, healthy, time.Now())
        enabled := state.AutoScan
        mode := state.FrontMode
        saveStateLocked() // v3.18 fix: scan results could be lost on restart when the IR probe goroutine bailed early
        stateMu.Unlock()

        // v3.16→3.17 FIX: the front probe is a NETWORK call (TLS dial + HTTP
        // request, up to ~14s per candidate; the IR verdict adds up to ~55s
        // per candidate via check-host). It used to run while holding
        // stateMu.Lock() — every API/sub request in the whole panel froze for
        // its duration. Probe OUTSIDE the lock, then store the result inside.
        // v3.17: every candidate is evaluated from BOTH vantages (panel +
        // Iran) and the first IR-alive one is activated; the other proven
        // candidates stay in state.FrontPicks and ride along in every
        // subscription as 🎭 variants (links.go) so a single SNI blocklist
        // entry can no longer kill every link at once.
        edge := healthy[0].IP
        front := applyFrontsFrom(mode, func(b string, r bool) error {
                return frontProbe(edge, domain, b, r)
        }, frontIRVerdict)

        // v3.15: self-test every transport end-to-end with the fresh SNI +
        // probe the edges/domain from Iranian vantage points (background).
        go doctorRun()
        go irProbeAll()

        best := healthy[0]
        city := best.City
        if city == "" {
                city = best.CC
        }
        logf("auto-scan: %d/%d edges healthy — applied top %d (best %s %s: %.0fms, %.0f KB/s, loss 0) front=%q",
                len(healthy), len(edges), len(healthy), best.IP, city, best.Med, best.SpeedKbps, front)
        msg := fmt.Sprintf("بهترین لبه: %s (%s) — پینگ %.0fms · پکت‌لاست ۰ · %.0f KB/s — در کانفیگ‌ها جایگزاری شد",
                best.IP, orStr(city, "—"), best.Med, best.SpeedKbps)
        if front != "" {
                msg += fmt.Sprintf(" · جلوی SNI فعال شد (%s)", front)
        }
        if !enabled {
                msg += " (اسکن خودکار خاموش است — فقط این بار اجرا شد)"
        }
        _ = newAddr
        return true, msg
}

// autoScanEnabled / autoScanLastAt are tiny locked readers.
func autoScanEnabled() bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state.AutoScan
}

func autoScanLastAt() int64 {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state.AutoScanAt
}

// autoScanLoop: first run 90s after boot, then every 5 min decide whether the
// (default 1h) cadence is due — cheap check, heavy work stays rare.
func autoScanLoop() {
        go func() {
                time.Sleep(90 * time.Second)
                if autoScanEnabled() {
                        autoScanOnce()
                }
                t := time.NewTicker(5 * time.Minute)
                defer t.Stop()
                for range t.C {
                        if !autoScanEnabled() {
                                continue
                        }
                        if time.Since(time.Unix(autoScanLastAt(), 0)) >= autoScanInterval() {
                                autoScanOnce()
                        }
                }
        }()
}

// autoScanSummary is the compact status block embedded in statePayload —
// takes its own locks, so callers must NOT hold stateMu.
func autoScanSummary() map[string]any {
        doc, docAt, docRunning := doctorPayload()
        stateMu.RLock()
        hours := state.AutoScanHours
        frontHost := state.FrontSNI
        frontRand := state.FrontRand
        frontAt := state.FrontAt
        frontMode := state.FrontMode
        frontIR := state.FrontIR
        frontIRAt := state.FrontIRAt
        frontPicks := append([]FrontPick(nil), state.FrontPicks...)
        domainIR := state.DomainIR
        domainIRAt := state.DomainIRAt
        stateMu.RUnlock()
        if hours < 1 || hours > 24 {
                hours = 1
        }
        return map[string]any{
                "enabled":     autoScanEnabled(),
                "last_run":    autoScanLastAt(),
                "auto_addr":   autoAddrNow(),
                "every_hours": hours,
                "front": map[string]any{
                        "active": frontHost != "",
                        "host":   frontHost,
                        "rand":   frontRand,
                        "at":     frontAt,
                        "mode":   frontMode,
                        // v3.16: 1 = the front SNI survives Iranian DPI (an IR
                        // node completed the TLS handshake), 2 = blocked
                        "ir":     frontIR,
                        "ir_at":  frontIRAt,
                        // v3.17: every proven candidate + its IR verdict — the
                        // non-active ones ride along in the sub as 🎭 variants
                        "picks":  frontPicks,
                },
                "doctor": map[string]any{
                        "results": doc,
                        "at":      docAt,
                        "running": docRunning,
                },
                "ir": map[string]any{
                        "domain":    domainIR,
                        "domain_at": domainIRAt,
                },
        }
}

func autoAddrNow() bool {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return state.AutoAddr
}

// autoScanPayload feeds the scanner view card + status API.
func autoScanPayload() map[string]any {
        stateMu.RLock()
        last := state.AutoScanAt
        edges := append([]*EdgeScore(nil), state.TopEdges...)
        multi := state.MultiEdge
        addr := state.Address
        stateMu.RUnlock()
        p := autoScanSummary()
        if autoScanEnabled() {
                v := int64(autoScanInterval().Seconds()) - int64(time.Since(time.Unix(last, 0)).Seconds())
                if v < 0 {
                        v = 0
                }
                p["next_in"] = v
        }
        p["running"] = autoScanRunning.Load()
        p["edges"] = edges
        p["multi"] = multi
        p["address"] = addr
        p["every_s"] = int(autoScanInterval().Seconds())
        return p
}
