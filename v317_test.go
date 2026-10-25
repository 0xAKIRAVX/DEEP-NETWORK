package main

import (
        "strings"
        "testing"
        "time"
)

// ─────────── v3.17: Iran-aware front selection + 🎭 alternate-front variants ───────────

// The IR-aware selection must prefer the first candidate that survives the
// Iranian probes, not merely the first that probes fine from the panel:
// b-cdn.net probed OK from the panel while being blocked 0/6 from Iran —
// exactly the regression that made every user config return -1.
func TestEvaluateFrontsPrefersIRAlive(t *testing.T) {
        probe := func(base string, rand bool) error {
                if base == "fonts.bunny.net" {
                        return errFake // panel-side probe fails for the top candidate
                }
                return nil
        }
        ir := func(base string, rand bool) int {
                if base == "bunny.net" {
                        return 2 // blocked from every Iranian node
                }
                if base == "b-cdn.net" {
                        return 1 // alive from Iran
                }
                return -1
        }
        picks := evaluateFronts("", probe, ir)
        if len(picks) != 5 { // v3.19: all candidates except the failing fonts.bunny.net
                t.Fatalf("picks = %v, want the 5 proven candidates", picks)
        }
        pick, ok := pickFront(picks)
        if !ok || pick.Base != "b-cdn.net" {
                t.Fatalf("pick = %+v — the IR-alive candidate must win over the first-proven", pick)
        }
        if pick.IR != 1 {
                t.Fatalf("pick.IR = %d, want 1", pick.IR)
        }

        // no IR data at all (check-host down): fall back to the first proven
        picks2 := evaluateFronts("", probe, nil)
        pick2, ok2 := pickFront(picks2)
        if !ok2 || pick2.Base != "bunnycdn.com" { // v3.19: first proven is now bunnycdn.com (fonts fails)
                t.Fatalf("fallback pick = %+v, want first proven", pick2)
        }
        if pick2.IR != -1 {
                t.Fatalf("no-irCheck pick must stay unknown, got %d", pick2.IR)
        }
}

// Custom mode evaluates exactly the one custom candidate; off clears.
func TestEvaluateFrontsCustomAndOff(t *testing.T) {
        picks := evaluateFronts("*.myfront.example", func(b string, r bool) error { return nil }, nil)
        if len(picks) != 1 || picks[0].Base != "myfront.example" || !picks[0].Rand {
                t.Fatalf("custom picks = %+v", picks)
        }
        if got := evaluateFronts("off", func(b string, r bool) error { return nil }, nil); got != nil {
                t.Fatalf("off must produce no picks, got %v", got)
        }
        // unprovable custom candidate → no picks
        if got := evaluateFronts("broken.example", func(b string, r bool) error { return errFake }, nil); got != nil {
                t.Fatalf("failing custom must produce no picks, got %v", got)
        }
}

// applyFrontsFrom must activate the IR-alive candidate and persist every
// proven pick so the 🎭 link variants + UI can follow it.
func TestApplyFrontsFromStoresPicks(t *testing.T) {
        save := state
        state = &State{FrontSNI: "b-cdn.net", FrontRand: true, FrontAt: 42}
        defer func() { state = save }()

        got := applyFrontsFrom("", func(base string, rand bool) error {
                if base == "fonts.bunny.net" {
                        return errFake
                }
                return nil
        }, func(base string, rand bool) int {
                if base == "b-cdn.net" {
                        return 1
                }
                return 2
        })
        if got != "b-cdn.net" {
                t.Fatalf("applied front = %q, want the IR-alive b-cdn.net", got)
        }
        stateMu.RLock()
        defer stateMu.RUnlock()
        if state.FrontSNI != "b-cdn.net" || !state.FrontRand {
                t.Fatalf("active front = %q/%v", state.FrontSNI, state.FrontRand)
        }
        if state.FrontIR != 1 {
                t.Fatalf("legacy FrontIR = %d, want 1 (active front verdict)", state.FrontIR)
        }
        if len(state.FrontPicks) != 5 { // v3.19: five proven candidates ride the picks
                t.Fatalf("FrontPicks = %v, want all five proven candidates", state.FrontPicks)
        }
        if time.Now().Unix()-state.FrontPicksAt > 5 {
                t.Fatalf("FrontPicksAt not refreshed: %d", state.FrontPicksAt)
        }
}

// The subscription must carry one variant set per proven-but-inactive front
// (🎭 suffix, alternate SNI on the primary address) and must SKIP candidates
// measured blocked from every Iranian node.
func TestSubCarriesAlternateFronts(t *testing.T) {
        save := state
        defer func() { state = save }()
        state = &State{
                FrontSNI: "fonts.bunny.net", FrontRand: false,
                FrontPicks: []FrontPick{
                        {Base: "fonts.bunny.net", Rand: false, IR: 1, At: 1},
                        {Base: "bunny.net", Rand: false, IR: 1, At: 1},
                        {Base: "b-cdn.net", Rand: true, IR: 2, At: 1}, // blocked 0/6 from Iran
                },
        }
        c := &Client{Name: "main", ID: "6c4abbbe-e645-40fa-bf1b-84deac7cb7c1"}
        links := buildLinks(c, "deep-network-development-w4a86.lucity.app")

        var sawAlt, sawBlocked, sawPrimary int
        for _, l := range links {
                name := linkDisplayName(l) // decodes the URI fragment / vmess ps
                u := l.URL
                // v3.21: 🎭 fronts are ⟦ USER • PROTO • NET • BUNNY 🎭 ⟧ — the
                // short front label + the class icon inside the brackets.
                if strings.Contains(name, " 𝗕𝗨𝗡𝗡𝗬 🎭 ⟧") {
                        sawAlt++
                        if strings.HasPrefix(u, "vless://") && !strings.Contains(u, "sni=bunny.net") {
                                t.Fatalf("🎭 variant must carry its own SNI: %s", u)
                        }
                }
                if strings.Contains(name, "𝗕-𝗖𝗗𝗡 🎭") {
                        sawBlocked++
                }
                if strings.HasPrefix(u, "vless://") && strings.Contains(u, "sni=fonts.bunny.net") && !strings.Contains(name, "🎭") {
                        sawPrimary++
                }
        }
        if sawAlt < 4 {
                t.Fatalf("expected the bunny.net 🎭 variant set in the sub, saw %d links", sawAlt)
        }
        if sawBlocked != 0 {
                t.Fatalf("IR-blocked front must not ride along as a variant, saw %d links", sawBlocked)
        }
        // v3.21.2: the primary WS + HU rows carry the front (XHTTP moved to
        // its own direct-origin row with the panel domain as SNI — tested
        // in v319_test.go TestSubWSFirstXHTTPLastDirect).
        if sawPrimary < 2 {
                t.Fatalf("primary vless links must carry the active front SNI, saw %d", sawPrimary)
        }
}

// Guards: no active front (admin turned it off) → no variants; picks with
// unknown IR still ride along.
func TestAppendFrontAltsGuards(t *testing.T) {
        save := state
        defer func() { state = save }()
        c := &Client{Name: "main", ID: "6c4abbbe-e645-40fa-bf1b-84deac7cb7c1"}

        // front off → untouched
        state = &State{FrontPicks: []FrontPick{{Base: "bunny.net", IR: 1}}}
        out := buildLinks(c, "deep-network-development-w4a86.lucity.app")
        for _, l := range out {
                if strings.Contains(linkDisplayName(l), "🎭") {
                        t.Fatalf("front off must not emit 🎭 variants: %s", linkDisplayName(l))
                }
        }

        // unknown IR verdict → still emitted as an alternate
        state = &State{FrontSNI: "bunny.net", FrontPicks: []FrontPick{
                {Base: "bunny.net", IR: 1}, {Base: "fonts.bunny.net", IR: -1}}}
        out = buildLinks(c, "deep-network-development-w4a86.lucity.app")
        saw := 0
        for _, l := range out {
                if strings.Contains(linkDisplayName(l), " 𝗙𝗢𝗡𝗧𝗦 🎭") {
                        saw++
                }
        }
        if saw == 0 {
                t.Fatal("unknown-IR candidate must still ride along as 🎭 variant")
        }
}
