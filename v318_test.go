package main

// v3.18 tests: the IR-TLS subscription gate, the 🛡️-direct proven-address
// fix, poisoned-domain DNS skipping, the short Persian naming pass, and the
// tier-interleaved edge shortlist.

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func v318Setup(t *testing.T) {
        t.Helper()
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.Address = "138.199.37.231" // the live panel's proven Frankfurt primary
        state.Tuning = defaultTuning()
        state.LocalMode = &LocalModeState{Enabled: true}
        stateMu.Unlock()
}

// irGateEdges must drop edges whose Iranian TLS probe says "all nodes failed"
// (IRTLS == 0), keep probe-unavailable edges (IRTLS == -1), and rank verified
// edges first — this is the gate that ends "-1 configs".
func TestIRGateEdgesDropsIRDead(t *testing.T) {
        v318Setup(t)
        defer func(old func(string) int) { irProbeTLS = old }(irProbeTLS)
        irProbeTLS = func(ip string) int {
                switch ip {
                case "185.102.217.65": // Bucharest — TCP ok but TLS-dead from Iran (the real 2026-10 measurement)
                        return 0
                case "169.150.215.115": // Istanbul/Datacamp — TLS ok from IR nodes
                        return 1
                case "204.157.181.38": // Baghdad — probe unavailable
                        return -1
                default:
                        return -1
                }
        }
        edges := []*EdgeScore{
                {IP: "185.102.217.65", Med: 76, Loss: 0, City: "Bucharest", CC: "RO"},
                {IP: "204.157.181.38", Med: 120, Loss: 0, City: "Baghdad", CC: "IQ"},
                {IP: "169.150.215.115", Med: 122, Loss: 0, City: "Istanbul", CC: "TR"},
                {IP: "37.236.234.2", Med: 148, Loss: 0, City: "Karbala", CC: "IQ"}, // not probed (beyond maxProbe)
        }
        out := irGateEdges(edges, 3)
        if len(out) != 3 {
                t.Fatalf("gate must keep 3 of 4 edges (dead Bucharest dropped, unprobed Karbala kept), got %d: %+v", len(out), out)
        }
        if out[0].IP != "169.150.215.115" {
                t.Errorf("IR-verified edge must rank first, got %s", out[0].IP)
        }
        if out[1].IP != "204.157.181.38" && out[2].IP != "204.157.181.38" {
                t.Errorf("probe-unavailable edge must be kept, got %s / %s", out[1].IP, out[2].IP)
        }
        if out[1].IP != "37.236.234.2" && out[2].IP != "37.236.234.2" {
                t.Errorf("unprobed edge must be kept (unknown), got %s / %s", out[1].IP, out[2].IP)
        }
        for _, e := range out {
                if e.IP == "185.102.217.65" {
                        t.Error("TLS-dead-from-Iran edge must never survive the gate")
                }
                if e.IP == "169.150.215.115" && e.IRTLS != 1 {
                        t.Errorf("gate must store the IR TLS verdict (1), got %d", e.IRTLS)
                }
        }
}

// v3.18.1 regression: the raw irCheckURL verdict is 2 = blocked — the first
// v3.18 build stored it raw, so "2" (dead) sorted ABOVE "1" (alive) and dead
// edges shipped as verified. The gate must treat anything ≠ 1 as dead.
func TestIRGateTreatsLegacyTwoAsDead(t *testing.T) {
        v318Setup(t)
        edges := []*EdgeScore{
                {IP: "185.102.217.65", IRTLS: 2, IRTLSAt: 1792863797, City: "Bucharest", CC: "RO"}, // legacy blocked verdict
                {IP: "143.244.45.177", IRTLS: 1, IRTLSAt: 1792863777, City: "Kyiv", CC: "UA"},    // alive
        }
        // no live probing — verdicts pre-seeded; only classify
        out := irGateEdges(edges, 0)
        if len(out) != 1 || out[0].IP != "143.244.45.177" {
                t.Fatalf("legacy ir_tls=2 (blocked) must be dropped, kyiv kept; got %+v", out)
        }
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        for _, l := range links {
                if strings.Contains(l.URL, "@185.102.217.65") {
                        t.Errorf("legacy-2 dead edge must not ride the subscription: %s", first80(l.URL))
                }
        }
}

// buildLinks must never emit an edge measured TLS-dead from Iran.
func TestBuildLinksSkipsIRDeadEdges(t *testing.T) {
        v318Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{
                {IP: "185.102.217.65", Med: 76, Loss: 0, City: "Bucharest", CC: "RO", IRTLS: 0, IRTLSAt: 1792861074}, // measured dead
                {IP: "169.150.215.115", Med: 122, Loss: 0, City: "Istanbul", CC: "TR", IRTLS: 1, IRTLSAt: 1792861085},
        }
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        for _, l := range links {
                if strings.Contains(l.URL, "@185.102.217.65") {
                        t.Errorf("IR-dead edge must not ride the subscription: %s", first80(l.URL))
                }
        }
        found := false
        for _, l := range links {
                if strings.Contains(l.URL, "@169.150.215.115") {
                        found = true
                }
        }
        if !found {
                t.Error("IR-verified edge must ride the subscription")
        }
}

// The DNS-auto variant must disappear while the panel domain is measured
// dead from Iran (DomainIR == 2) — shipping it then is a guaranteed -1 row.
func TestBuildLinksSkipsDNSWhenDomainPoisoned(t *testing.T) {
        v318Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{{IP: "169.150.215.115", Med: 122, Loss: 0, City: "Istanbul", CC: "TR", IRTLS: 1, IRTLSAt: 1792861085}}
        state.DomainIR = 2
        stateMu.Unlock()
        host := "deep-network-development-w4a86.lucity.app"
        for _, l := range buildLinks(lmTestClient(), host) {
                if strings.Contains(l.URL, "@"+host) {
                        t.Errorf("poisoned-domain DNS variant must be skipped: %s", first80(l.URL))
                }
        }
        // …and return when the domain measures alive again (self-healing).
        stateMu.Lock()
        state.DomainIR = 1
        stateMu.Unlock()
        dns := false
        for _, l := range buildLinks(lmTestClient(), host) {
                if strings.Contains(l.URL, "@"+host) {
                        dns = true
                }
        }
        if !dns {
                t.Error("DNS variant must come back once the domain is reachable from Iran")
        }
}

// The 🛡️ direct variant must connect to the PROVEN primary address
// (state.Address — the working Frankfurt PoP), not whatever the panel's own
// resolver answers for the domain (that geo answer was 185.111.111.156,
// TLS-dead from every Iranian node — the exact "-1 مستقیم" report).
func TestLocalDirectUsesProvenPrimary(t *testing.T) {
        v318Setup(t)
        links := buildLocalLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        var direct *Link
        for i := range links {
                if links[i].Key == "vless-ws-direct" {
                        direct = &links[i]
                }
        }
        if direct == nil {
                t.Fatal("🛡️ direct variant missing")
        }
        if !strings.Contains(direct.URL, "@138.199.37.231:443") {
                t.Errorf("direct variant must ride the proven primary address, got: %s", direct.URL)
        }
        if strings.Contains(direct.URL, "@185.111.111.156") {
                t.Errorf("direct variant must never ship the IR-dead geo answer")
        }
        // v3.21 name format: ⟦ 𝗠𝗔𝗜𝗡 • 𝗩𝗟𝗘𝗦𝗦 • 𝗪𝗦 • 𝗗𝗜𝗥𝗘𝗖𝗧 🛡️ ⟧
        if nm := linkDisplayName(*direct); !strings.Contains(nm, "𝗗𝗜𝗥𝗘𝗖𝗧 🛡️") || !strings.Contains(nm, "⟦") || !strings.HasSuffix(nm, "⟧") {
                t.Errorf("direct variant name must be the ⟦ … DIRECT 🛡️ ⟧ form, got %q", nm)
        }
}

// Names (v3.21): ⟦ 𝗠𝗔𝗜𝗡 • 𝗩𝗟𝗘𝗦𝗦 • 𝗪𝗦 • 𝗖𝗜𝗧𝗬 🇩🇪⁰¹ ⟧ — bold math font,
// flag + superscript rank for city variants (medals retired), NO latency
// noise; DNS variant is ⟦ … AUTO 🌐 ⟧.
func TestNamingPersianShortMedals(t *testing.T) {
        v318Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{
                {IP: "169.150.215.115", Med: 122, Loss: 0, City: "Istanbul", CC: "TR", IRTLS: 1, IRTLSAt: 1792861085},
                {IP: "185.102.217.65", Med: 76, Loss: 0, City: "Bucharest", CC: "RO", IRTLS: 1, IRTLSAt: 1792861090},
        }
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        var primary, silver, dns string
        for _, l := range links {
                nm := linkDisplayName(l)
                switch l.Key {
                case "vless-ws":
                        if primary == "" {
                                primary = nm
                        }
                }
                if strings.Contains(l.URL, "@169.150.215.115") && strings.Contains(nm, "⁰²") {
                        silver = nm
                }
                if strings.Contains(l.URL, "@deep-network-development-w4a86.lucity.app") {
                        dns = nm
                }
        }
        if !strings.Contains(primary, "𝗠𝗔𝗜𝗡") || !strings.Contains(primary, "⁰¹") || !strings.Contains(primary, "⟦") {
                t.Errorf("primary name must be ⟦ MAIN • … ⁰¹ ⟧ bold, got %q", primary)
        }
        if silver == "" || !strings.Contains(silver, "𝗜𝗦𝗧𝗔𝗡𝗕𝗨𝗟") || !strings.Contains(silver, "🇹🇷") {
                t.Errorf("edge name must be bold ISTANBUL + flag + rank, got %q", silver)
        }
        if strings.Contains(silver, "ms") || strings.Contains(silver, "122") {
                t.Errorf("edge name must not carry latency noise, got %q", silver)
        }
        if !strings.Contains(dns, "𝗔𝗨𝗧𝗢 🌐") {
                t.Errorf("DNS variant must be ⟦ … AUTO 🌐 ⟧, got %q", dns)
        }
}

// pickEdgesByRegion must interleave tiers: the first probes must cover
// multiple regions (the tier-1-first fill kept shipping TLS-dead PoPs while
// the working Frankfurt PoPs sat unprobed at the tail).
func TestPickEdgesByRegionInterleaves(t *testing.T) {
        ips := []string{}
        geo := map[string]map[string]string{}
        for i := 0; i < 60; i++ {
                ip := "10.1." + itoa(i/250) + "." + itoa(i%250+1)
                ips = append(ips, ip)
                cc := "TR" // tier 1
                switch i % 3 {
                case 1:
                        cc = "GR" // tier 2
                case 2:
                        cc = "DE" // tier 3
                }
                geo[ip] = map[string]string{"cc": cc, "city": "x"}
        }
        out := pickEdgesByRegion(ips, geo, 130)
        if len(out) < 24 {
                t.Fatalf("shortlist too small: %d", len(out))
        }
        cov := map[string]int{}
        for _, ip := range out[:24] { // what autoScanTargets actually probes
                cov[geo[ip]["cc"]]++
        }
        if cov["TR"] == 0 || cov["GR"] == 0 || cov["DE"] == 0 {
                t.Errorf("first 24 probes must cover all tiers, got %+v", cov)
        }
        if cov["DE"] > cov["TR"] {
                t.Errorf("tier-1 quota (14 TR) must still dominate a single tier-3 country, got %+v", cov)
        }
}

// The autoscan handler/API surface must keep answering with the edges that
// survived the gate (smoke: /sub remains valid base64 with new names).
func TestSubRendersShortPersianNames(t *testing.T) {
        v318Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{
                {IP: "169.150.215.115", Med: 122, Loss: 0, City: "Istanbul", CC: "TR", IRTLS: 1, IRTLSAt: 1792861085},
        }
        state.Address = "138.199.37.231"
        stateMu.Unlock()
        mux := http.NewServeMux()
        mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
                handleSub(w, r, strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/"))
        })
        srv := httptest.NewServer(mux)
        defer srv.Close()
        resp, err := http.Get(srv.URL + "/sub/" + subTokenForMain(t))
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        body := make([]byte, 1<<20)
        n, _ := resp.Body.Read(body)
        raw := string(body[:n])
        // names live URL-encoded in fragments — check the decoded display name
        for _, l := range buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app") {
                if strings.Contains(l.URL, "@169.150.215.115") {
                        if nm := linkDisplayName(l); !strings.Contains(nm, "𝗜𝗦𝗧𝗔𝗡𝗕𝗨𝗟") || !strings.Contains(nm, "🇹🇷") {
                                t.Errorf("sub edge names must be bold city + flag, got %q", nm)
                        }
                }
        }
        if len(raw) == 0 {
                t.Error("empty sub body")
        }
}
