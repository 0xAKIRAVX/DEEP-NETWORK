package main

// v3.19 tests: the expanded SNI-front candidate set (bunnycdn.com /
// dash.bunny.net / docs.bunny.net), the admin edge blocklist (ground truth
// for ISPs the probe nodes cannot see), and the XHTTP-first transport order
// (pattern-resistant transport is the one v2rayNG auto-picks).

import (
        "strings"
        "testing"
)

func v319Setup(t *testing.T) {
        t.Helper()
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.Address = "138.199.37.231" // live panel's proven Frankfurt primary
        state.Tuning = defaultTuning()
        state.LocalMode = &LocalModeState{Enabled: true}
        state.FrontSNI, state.FrontRand = "fonts.bunny.net", false
        stateMu.Unlock()
}

// The candidate list must carry the three new bunny-owned zones (each with
// its own exact certificate — verified live) ahead of bunny.net, with the
// Iran-blocked *.b-cdn.net wildcard still last.
func TestFrontCandidatesV319(t *testing.T) {
        want := []string{"fonts.bunny.net", "bunnycdn.com", "dash.bunny.net", "docs.bunny.net", "bunny.net", "b-cdn.net"}
        if len(frontCandidates) != len(want) {
                t.Fatalf("candidate list changed: %+v", frontCandidates)
        }
        for i, w := range want {
                if frontCandidates[i].base != w {
                        t.Errorf("candidate[%d] = %q, want %q", i, frontCandidates[i].base, w)
                }
        }
        // evaluateFronts with every probe passing + IR alive only for the first
        // four must produce picks in order and pickFront must choose fonts.
        picks := evaluateFronts("auto", func(base string, rand bool) error { return nil },
                func(base string, rand bool) int {
                        if base == "bunny.net" || base == "b-cdn.net" {
                                return 2 // blocked from every IR node
                        }
                        return 1
                })
        if len(picks) != 6 {
                t.Fatalf("all 6 candidates must be evaluated, got %d", len(picks))
        }
        pick, ok := pickFront(picks)
        if !ok || pick.Base != "fonts.bunny.net" {
                t.Fatalf("first IR-alive candidate must win, got %+v ok=%v", pick, ok)
        }
        // IR-blocked candidates must be recognizable in the picks (the 🎭 emitter skips them).
        blocked := 0
        for _, p := range picks {
                if p.IR == 2 {
                        blocked++
                }
        }
        if blocked != 2 {
                t.Errorf("bunny.net + b-cdn.net must carry ir=2, got %d blocked picks", blocked)
        }
}

// parseEdgeBlock accepts arrays and comma/space strings, keeps only IP
// literals, dedupes, and clears on empty.
func TestParseEdgeBlock(t *testing.T) {
        if got := parseEdgeBlock("195.181.166.158, 185.102.217.65 195.181.166.158"); len(got) != 2 || got[0] != "195.181.166.158" || got[1] != "185.102.217.65" {
                t.Errorf("string form: want 2 deduped IPs in order, got %v", got)
        }
        if got := parseEdgeBlock([]any{"195.181.166.158", "not-an-ip", "138.199.37.231"}); len(got) != 2 {
                t.Errorf("array form: invalid entries must be dropped, got %v", got)
        }
        if got := parseEdgeBlock(""); got != nil && len(got) != 0 {
                t.Errorf("empty must clear, got %v", got)
        }
        if got := parseEdgeBlock("bunny.net, , 1.2.3.4"); len(got) != 1 || got[0] != "1.2.3.4" {
                t.Errorf("domains must be rejected, got %v", got)
        }
}

// An edge on the admin blocklist must never ride the subscription — the
// probe nodes passed Stockholm 6/6 while the user's own ISP reported -1.
func TestBuildLinksSkipsBlockedEdges(t *testing.T) {
        v319Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.EdgeBlock = []string{"195.181.166.158"} // user-reported dead (Stockholm)
        state.TopEdges = []*EdgeScore{
                {IP: "195.181.166.158", Med: 79, Loss: 0, City: "Stockholm", CC: "SE", IRTLS: 1, IRTLSAt: 1792861085},
                {IP: "143.244.45.177", Med: 76, Loss: 0, City: "Kyiv", CC: "UA", IRTLS: 1, IRTLSAt: 1792861085},
        }
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        for _, l := range links {
                if strings.Contains(l.URL, "@195.181.166.158") {
                        t.Errorf("admin-blocked edge must never ride the subscription: %s", first80(l.URL))
                }
        }
        found := false
        for _, l := range links {
                if strings.Contains(l.URL, "@143.244.45.177") {
                        found = true
                }
        }
        if !found {
                t.Error("non-blocked IR-verified edge must still ride the subscription")
        }
}

// localDirectAddr must never point the 🛡️ direct variant at a blocked edge.
func TestLocalDirectSkipsBlockedEdges(t *testing.T) {
        v319Setup(t)
        stateMu.Lock()
        state.Address = "" // force the TopEdges fallback path
        state.EdgeBlock = []string{"195.181.166.158"}
        state.TopEdges = []*EdgeScore{
                {IP: "195.181.166.158", IRTLS: 1},
                {IP: "143.244.45.177", IRTLS: 1},
        }
        stateMu.Unlock()
        got := localDirectAddr(LocalModeState{Enabled: true}, "deep-network-development-w4a86.lucity.app")
        if got == "195.181.166.158" {
                t.Fatalf("🛡️ direct must skip the blocked edge, got %s", got)
        }
        if got != "143.244.45.177" {
                t.Errorf("🛡️ direct should fall to the next IR-verified edge, got %s", got)
        }
}

// v3.21.2: WS must be the FIRST link of the primary set — v2rayNG keeps
// the first/lowest config active, and through the bunny edges WS is the
// measured-best transport (sustained 50MB COMPLETE at ~2MB/s). XHTTP rides
// LAST and DIRECT to the origin ingress: through bunny's h2 layer it stalls
// at 95-97% of every chunked transfer (2026-10-25 live incident — "config
// pings but nothing loads"), so it must never be the row a user taps first.
func TestSubWSFirstXHTTPLastDirect(t *testing.T) {
        v319Setup(t)
        injectOrigin(t, "deep-network-development-w4a86.lucity.app", "84.17.37.214", "Frankfurt", "DE")
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        if len(links) == 0 {
                t.Fatal("no links rendered")
        }
        if !strings.Contains(links[0].URL, "type=ws") {
                t.Errorf("first link must be WS, got %s", first80(links[0].URL))
        }
        // exactly one XHTTP row in the whole sub, direct to the origin
        sawX, xIdx := 0, -1
        for i, l := range links {
                if strings.Contains(l.URL, "type=xhttp") {
                        sawX++
                        xIdx = i
                }
        }
        if sawX != 1 {
                t.Fatalf("want exactly 1 direct XHTTP row, saw %d", sawX)
        }
        x := links[xIdx].URL
        if !strings.Contains(x, "@84.17.37.214:443") {
                t.Errorf("XHTTP must dial the origin IP, got %s", first80(x))
        }
        if !strings.Contains(x, "mode=packet-up") {
                t.Errorf("XHTTP must ride packet-up mode, got %s", first80(x))
        }
        if !strings.Contains(x, "sni=deep-network-development-w4a86.lucity.app") {
                t.Errorf("XHTTP SNI must be the panel domain (origin cert), got %s", first80(x))
        }
        if !strings.Contains(x, "host=deep-network-development-w4a86.lucity.app") {
                t.Errorf("XHTTP host header must be the panel domain, got %s", first80(x))
        }
        if xIdx < 3 {
                t.Errorf("XHTTP must ride LAST in the primary group, got index %d", xIdx)
        }
}

// The 🎭 alternate-front emitter must cap at three variant sets, skipping
// the active front and every IR-blocked candidate.
func TestAppendFrontAltsCapThree(t *testing.T) {
        v319Setup(t)
        stateMu.Lock()
        state.FrontPicks = []FrontPick{
                {Base: "fonts.bunny.net", IR: 1},
                {Base: "bunnycdn.com", IR: 1},
                {Base: "dash.bunny.net", IR: 1},
                {Base: "docs.bunny.net", IR: 1},
                {Base: "bunny.net", IR: 1},
                {Base: "b-cdn.net", Rand: true, IR: 2},
        }
        stateMu.Unlock()
        c := lmTestClient()
        base := buildLinksAddr(c, "138.199.37.231", "deep-network-development-w4a86.lucity.app", " x", true)
        out := appendFrontAlts(c, "138.199.37.231", "deep-network-development-w4a86.lucity.app", base)
        sets := 0
        for _, l := range out {
                if strings.Contains(l.URL, "sni=bunnycdn.com") {
                        sets++
                        break
                }
        }
        for _, l := range out {
                if strings.Contains(l.URL, "sni=dash.bunny.net") {
                        sets++
                        break
                }
        }
        for _, l := range out {
                if strings.Contains(l.URL, "sni=docs.bunny.net") {
                        sets++
                        break
                }
        }
        if sets != 3 {
                t.Errorf("three alternate fronts must ride along, saw %d", sets)
        }
        for _, l := range out {
                if strings.Contains(l.URL, "sni=bunny.net&") {
                        t.Errorf("4th alternate (bunny.net) must be beyond the cap, saw %s", first80(l.URL))
                }
        }
}
