package main

// ─────────── v3.15→3.17: جلوی SNI / SNI front + انتخاب آگاه از ایران ───────────
// WHY THIS EXISTS (measured, not theory): the panel domain family is
// DNS-poisoned inside Iran while the bunny edge IPs themselves stay
// TCP-reachable. Every subscription link therefore carries a literal IP
// address — but the TLS SNI must not be a name the Iranian DPI kills.
//
// v3.15 shipped bunny's shared wildcard (*.b-cdn.net) as the front. v3.17
// REALITY CHECK (2026-10, check-host 6 Iranian nodes): b-cdn.net now times
// out from ALL 6 nodes (0/6) while fonts.bunny.net and bunny.net answer
// 6/6 — Iran blocks the shared b-cdn.net zone domain. Because EVERY link
// carried it, every link died with -1, exactly as the user reported.
//
// THE v3.17 SYSTEM:
//   * candidates are REAL bunny zones (valid certificates, strict TLS,
//     Host-header routing to this panel — proven by frontProbe);
//   * every scan also measures each candidate from IRANIAN vantage points
//     (check-host IR nodes) and activates the first one that survives;
//   * the remaining proven candidates are kept in state.FrontPicks and ride
//     along in every subscription as 🎭 variants (links.go) — blocking ONE
//     front domain can no longer kill every config at once;
//   * a 15-minute watchdog (frontWatchLoop) re-checks the ACTIVE front from
//     Iran and re-selects within minutes when the DPI blocks it mid-day.

import (
        "bufio"
        "crypto/tls"
        "fmt"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

// frontCandidates are tried in order (auto mode). Order rationale
// (2026-10 measurements from Iran): fonts.bunny.net is embedded by an
// enormous number of ordinary websites (an ISP blocking it breaks normal
// Iranian sites), bunny.net is the vendor apex, and the shared *.b-cdn.net
// wildcard stays as the last resort — Iran currently blocks it 6/6, but it
// may come back and it still works outside Iran.
var frontCandidates = []struct {
        base string
        rand bool
}{
        {"fonts.bunny.net", false},
        {"bunny.net", false},
        {"b-cdn.net", true},
}

// FrontPick is one PROVEN front candidate together with its Iranian-vantage
// verdict (ir: -1 unknown · 0 probe unavailable · 1 alive from Iran ·
// 2 blocked from every IR node).
type FrontPick struct {
        Base string `json:"base"`
        Rand bool   `json:"rand,omitempty"`
        IR   int    `json:"ir,omitempty"`
        At   int64  `json:"at,omitempty"`
}

// frontName renders the concrete TLS SNI for one link emission.
func frontName(base string, rand bool) string {
        if rand {
                return "ng" + randHex(5) + "." + base
        }
        return base
}

// frontProbe proves one front candidate against an edge IP:
//   1. strict TLS handshake — the served certificate must cover the front
//      name (no allowInsecure anywhere);
//   2. a real request with Host: <domain> must be answered by this panel
//      (any non-5xx status line proves the routing).
func frontProbe(edgeIP, domain, base string, rand bool) error {
        sni := frontName(base, rand)
        d := &net.Dialer{Timeout: 6 * time.Second}
        conn, err := tls.DialWithDialer(d, "tcp", edgeIP+":443", &tls.Config{
                ServerName: sni,
                // strict verification — this is exactly what users' cores do
        })
        if err != nil {
                return fmt.Errorf("TLS: %v", err)
        }
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(8 * time.Second))
        req, _ := http.NewRequest(http.MethodGet, "http://"+domain+"/panel/", nil)
        req.Host = domain
        if err := req.Write(conn); err != nil {
                return fmt.Errorf("write: %v", err)
        }
        br := bufio.NewReader(conn)
        resp, err := http.ReadResponse(br, req)
        if err != nil {
                return fmt.Errorf("read: %v", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode >= 500 {
                return fmt.Errorf("edge answered %d", resp.StatusCode)
        }
        return nil
}

// evaluateFronts probes every candidate (auto mode) or the single custom one
// and attaches the Iranian-vantage verdict to each PROVEN candidate. Pure
// network work — must be called with NO stateMu held. irCheck may be nil
// (panel-vantage-only, used by the admin custom-front path).
func evaluateFronts(mode string, probe func(base string, rand bool) error, irCheck func(base string, rand bool) int) []FrontPick {
        mode = strings.ToLower(strings.TrimSpace(mode))
        if mode == "off" {
                return nil
        }
        type cand struct {
                base string
                rand bool
        }
        var cands []cand
        if mode != "" && mode != "auto" {
                base := strings.TrimPrefix(strings.TrimPrefix(mode, "*."), ".")
                rand := strings.HasPrefix(mode, "*") || strings.HasPrefix(mode, ".")
                cands = append(cands, cand{base, rand})
        } else {
                for _, c := range frontCandidates {
                        cands = append(cands, cand{c.base, c.rand})
                }
        }
        now := time.Now().Unix()
        var picks []FrontPick
        for _, c := range cands {
                if probe(c.base, c.rand) != nil {
                        continue
                }
                p := FrontPick{Base: c.base, Rand: c.rand, IR: -1, At: now}
                if irCheck != nil {
                        p.IR = irCheck(c.base, c.rand)
                }
                picks = append(picks, p)
        }
        return picks
}

// pickFront selects the active front among evaluated picks: the first
// IR-alive candidate, falling back to the first proven one.
func pickFront(picks []FrontPick) (FrontPick, bool) {
        for _, p := range picks {
                if p.IR == 1 {
                        return p, true
                }
        }
        if len(picks) > 0 {
                return picks[0], true
        }
        return FrontPick{}, false
}

// applyFront is the pure, LOCK-FREE composition kept for unit tests — it must
// never be called on the global state while holding stateMu (v3.16: the
// production call sites use chooseFront + applyFrontChoice so the network
// probe runs with no lock held anywhere).
func applyFront(st *State, mode string, probe func(base string, rand bool) error) (applied string) {
        base, rand := chooseFront(mode, probe)
        applyFrontChoice(st, base, rand)
        return base
}

// chooseFront is the decision half (network probe, NO state access — must be
// called with NO stateMu held): mode "" (auto) walks frontCandidates in order;
// "off" disables; any other value is a custom base domain ("*.x" implies a
// random label).
func chooseFront(mode string, probe func(base string, rand bool) error) (string, bool) {
        mode = strings.ToLower(strings.TrimSpace(mode))
        if mode == "off" {
                return "", false
        }
        if mode != "" && mode != "auto" {
                base := strings.TrimPrefix(strings.TrimPrefix(mode, "*."), ".")
                rand := strings.HasPrefix(mode, "*") || strings.HasPrefix(mode, ".")
                if probe(base, rand) == nil {
                        return base, rand
                }
                return "", false
        }
        for _, cand := range frontCandidates {
                if probe(cand.base, cand.rand) == nil {
                        return cand.base, cand.rand
                }
        }
        return "", false
}

// applyFrontChoice is the state-write half — caller MUST hold stateMu.
// ("", false) clears the front.
func applyFrontChoice(st *State, base string, rand bool) {
        if base == "" {
                st.FrontSNI, st.FrontRand, st.FrontAt = "", false, 0
                return
        }
        st.FrontSNI, st.FrontRand, st.FrontAt = base, rand, time.Now().Unix()
}

// frontFromState renders the current front SNI ("" = no front).
func frontFromState() string {
        stateMu.RLock()
        base, rand := state.FrontSNI, state.FrontRand
        stateMu.RUnlock()
        if base == "" {
                return ""
        }
        return frontName(base, rand)
}

// frontSelMu serializes front re-selections (hourly scan vs 15-min watchdog
// vs admin POST) so two evaluations cannot interleave their state writes.
var frontSelMu sync.Mutex

// applyFrontsFrom evaluates the candidates for a mode, activates the picked
// one and stores every proven pick for the 🎭 link variants. All network work
// runs with NO stateMu held (v3.16 rule); the state write happens under
// stateMu only. Returns the applied base ("" = cleared).
func applyFrontsFrom(mode string, probe func(base string, rand bool) error, irCheck func(base string, rand bool) int) string {
        frontSelMu.Lock()
        defer frontSelMu.Unlock()
        picks := evaluateFronts(mode, probe, irCheck)
        pick, ok := pickFront(picks)
        stateMu.Lock()
        if ok {
                applyFrontChoice(state, pick.Base, pick.Rand)
                for _, p := range picks {
                        if p.Base == pick.Base && p.IR >= 0 {
                                state.FrontIR, state.FrontIRAt = p.IR, p.At
                        }
                }
        } else {
                applyFrontChoice(state, "", false)
        }
        state.FrontPicks, state.FrontPicksAt = picks, time.Now().Unix()
        stateMu.Unlock()
        saveState()
        if ok {
                return pick.Base
        }
        return ""
}

// switchToFront activates one already-proven pick (self-heal path — no new
// probes, the pick was proven by the last scan).
func switchToFront(p FrontPick) {
        frontSelMu.Lock()
        defer frontSelMu.Unlock()
        stateMu.Lock()
        applyFrontChoice(state, p.Base, p.Rand)
        if p.IR >= 0 {
                state.FrontIR, state.FrontIRAt = p.IR, p.At
        }
        saveStateLocked()
        stateMu.Unlock()
}

// bestEdgeForProbe returns a concrete edge IP for front probes.
func bestEdgeForProbe() string {
        stateMu.RLock()
        defer stateMu.RUnlock()
        if len(state.TopEdges) > 0 {
                return state.TopEdges[0].IP
        }
        if a := strings.TrimSpace(state.Address); isIPLiteral(a) {
                return a
        }
        return ""
}

// frontWatchLoop re-checks the ACTIVE front from Iranian nodes every 15
// minutes; when the DPI blocks it mid-day the front is re-selected within
// minutes instead of waiting for the next hourly scan.
func frontWatchLoop() {
        go func() {
                time.Sleep(10 * time.Minute)
                t := time.NewTicker(15 * time.Minute)
                defer t.Stop()
                for range t.C {
                        front := frontFromState()
                        if front == "" {
                                continue
                        }
                        if irCheckURL("https://"+front+"/") != 2 {
                                continue // alive or probe unavailable — nothing to do
                        }
                        logf("front watch: %q blocked from Iran — re-selecting front", front)
                        mode := func() string {
                                stateMu.RLock()
                                defer stateMu.RUnlock()
                                return state.FrontMode
                        }()
                        domain := autoScanDomain()
                        edge := bestEdgeForProbe()
                        if domain == "" || edge == "" {
                                continue
                        }
                        if base := applyFrontsFrom(mode, func(b string, r bool) error {
                                return frontProbe(edge, domain, b, r)
                        }, frontIRVerdict); base != "" {
                                go doctorRun()
                        }
                }
        }()
}
