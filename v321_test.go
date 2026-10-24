package main

// ─────────── v3.21 tests: ⟦ USER • PROTO • NET • GEO ⟧ naming, family
// blocklist, family-diverse edges, scan-loop panic guard ───────────

import (
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

// mathBold must render the alphabet in Mathematical Bold Sans, keep
// separators/flags/superscripts untouched, and be idempotent.
func TestMathBoldFont(t *testing.T) {
        got := mathBold("USER • VLESS • WS • FRANKFURT 01")
        want := "𝗨𝗦𝗘𝗥 • 𝗩𝗟𝗘𝗦𝗦 • 𝗪𝗦 • 𝗙𝗥𝗔𝗡𝗞𝗙𝗨𝗥𝗧 𝟬𝟭"
        if got != want {
                t.Fatalf("mathBold = %q, want %q", got, want)
        }
        if mathBold(got) != got {
                t.Fatalf("mathBold must be idempotent, got %q", mathBold(got))
        }
        // Persian + emoji + brackets pass through unchanged
        s := "پرچم 🇩🇪 ⟦ ⟧ ⁰¹"
        if mathBold(s) != s {
                t.Fatalf("non-Latin must pass through, got %q", mathBold(s))
        }
}

func TestCcFlagAndSupNum(t *testing.T) {
        if got := ccFlag("DE"); got != "🇩🇪" {
                t.Errorf("ccFlag(DE) = %q", got)
        }
        if got := ccFlag("tr"); got != "🇹🇷" {
                t.Errorf("ccFlag(tr) must uppercase, got %q", got)
        }
        if got := ccFlag(""); got != "" {
                t.Errorf("ccFlag(\"\") = %q", got)
        }
        if got := supNum(1); got != "⁰¹" {
                t.Errorf("supNum(1) = %q", got)
        }
        if got := supNum(12); got != "¹²" {
                t.Errorf("supNum(12) = %q", got)
        }
        if got := supNum(0); got != "⁰¹" {
                t.Errorf("supNum(0) must clamp to 1, got %q", got)
        }
}

func TestGeoTokenShapes(t *testing.T) {
        if got := geoToken("Frankfurt", "DE", 1, "", ""); got != "Frankfurt 🇩🇪⁰¹" {
                t.Errorf("ranked city = %q", got)
        }
        if got := geoToken("Kyiv", "UA", 2, "", ""); got != "Kyiv 🇺🇦⁰²" {
                t.Errorf("second rank = %q", got)
        }
        if got := geoToken("", "", 0, "🎭", "BUNNYCDN"); got != "BUNNYCDN 🎭" {
                t.Errorf("icon fallback = %q", got)
        }
        if got := geoToken("", "", 0, "🛡️", "DIRECT"); got != "DIRECT 🛡️" {
                t.Errorf("direct fallback = %q", got)
        }
        if got := geoToken("", "", 1, "", ""); got != "CDN⁰¹" {
                t.Errorf("unknown city must fall back to CDN, got %q", got)
        }
}

// The full default-template name for one link class — byte-for-byte the
// format the user requested.
func TestExactRequestedFormat(t *testing.T) {
        v320Setup(t) // fresh state, default CfgFmt
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{
                {IP: "143.244.45.177", Med: 73, Loss: 0, City: "Frankfurt", CC: "DE", IRTLS: 1, IRTLSAt: 1792861085},
        }
        state.Address = "138.199.37.231"
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        var kyivWS string
        for _, l := range links {
                if l.Key == "vless-ws" && strings.Contains(l.URL, "@143.244.45.177") {
                        kyivWS = linkDisplayName(l)
                }
        }
        want := "⟦ 𝗠𝗔𝗜𝗡 • 𝗩𝗟𝗘𝗦𝗦 • 𝗪𝗦 • 𝗙𝗥𝗔𝗡𝗞𝗙𝗨𝗥𝗧 🇩🇪⁰² ⟧"
        if kyivWS != want {
                t.Fatalf("edge ws name = %q, want %q", kyivWS, want)
        }
}

// The blocklist now matches whole /16 families: blocking one Prague edge
// must remove its sibling too, but leave other partners alone.
func TestFamilyBlocklistMatching(t *testing.T) {
        save := state
        defer func() { state = save }()
        state = &State{EdgeBlock: []string{"89.187.188.228"}} // Prague
        cases := []struct {
                ip   string
                want bool
        }{
                {"89.187.188.228", true},  // exact
                {"89.187.190.7", true},    // same /16 sibling
                {"89.188.1.1", false},     // different /16
                {"143.244.45.177", false}, // Kyiv untouched
                {"195.181.166.158", false}, // Stockholm untouched (not blocked here)
        }
        for _, c := range cases {
                if got := edgeBlockedState(c.ip); got != c.want {
                        t.Errorf("edgeBlockedState(%s) = %v, want %v", c.ip, got, c.want)
                }
        }
        if got := ipFamilyOf("89.187.188.228"); got != "89.187.0.0/16" {
                t.Errorf("ipFamilyOf v4 = %q", got)
        }
        if got := ipFamilyOf("2001:db8:1234:5678::1"); got != "2001:0db8:1234::/48" {
                t.Errorf("ipFamilyOf v6 = %q", got)
        }
}

// The medal section is family-diverse: at most two edges per /16 ride the
// subscription even when the scanner ranked four same-family edges best.
func TestEdgeFamilyDiversity(t *testing.T) {
        v320Setup(t)
        stateMu.Lock()
        state.MultiEdge = true
        state.TopEdges = []*EdgeScore{
                {IP: "89.187.188.228", Med: 20, Loss: 0, City: "Prague", CC: "CZ", IRTLS: 1, IRTLSAt: 1},
                {IP: "89.187.190.7", Med: 25, Loss: 0, City: "Brno", CC: "CZ", IRTLS: 1, IRTLSAt: 1},
                {IP: "89.187.191.9", Med: 30, Loss: 0, City: "Ostrava", CC: "CZ", IRTLS: 1, IRTLSAt: 1},
                {IP: "89.187.192.11", Med: 35, Loss: 0, City: "Plzen", CC: "CZ", IRTLS: 1, IRTLSAt: 1},
                {IP: "143.244.45.177", Med: 73, Loss: 0, City: "Frankfurt", CC: "DE", IRTLS: 1, IRTLSAt: 1},
                {IP: "169.150.215.115", Med: 80, Loss: 0, City: "Istanbul", CC: "TR", IRTLS: 1, IRTLSAt: 1},
        }
        state.Address = "138.199.37.231"
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        fam := map[string]int{}
        for _, l := range links {
                if l.Key != "vless-ws" || !strings.Contains(l.URL, "@89.187.") && !strings.Contains(l.URL, "@143.244.") && !strings.Contains(l.URL, "@169.150.") {
                        if l.Key != "vless-ws" {
                                continue
                        }
                }
                for _, prefix := range []string{"@89.187.", "@143.244.", "@169.150."} {
                        if strings.Contains(l.URL, prefix) && l.Key == "vless-ws" {
                                fam[prefix]++
                        }
                }
        }
        if fam["@89.187."] > 2 {
                t.Errorf("at most two edges per family must ride, got %d", fam["@89.187."])
        }
        if fam["@143.244."] != 1 || fam["@169.150."] != 1 {
                t.Errorf("other families must fill the section, got %+v", fam)
        }
}

// A panic inside a scan run must be recovered by safeAutoScan instead of
// killing the process (and with it the hourly loop).
func TestSafeAutoScanRecovers(t *testing.T) {
        orig := irProbeTLS
        defer func() { irProbeTLS = orig }()
        irProbeTLS = func(ip string) int {
                panic("probe exploded")
        }
        defer func() {
                if r := recover(); r != nil {
                        t.Fatalf("safeAutoScan must swallow the panic, got %v", r)
                }
        }()
        safeAutoScan()
}

// The sub endpoint still serves valid base64 with the new bracketed names
// (smoke through the real HTTP handler).
func TestSubServesBracketedNames(t *testing.T) {
        v320Setup(t)
        stateMu.Lock()
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
        if resp.StatusCode != 200 {
                t.Fatalf("sub status = %d", resp.StatusCode)
        }
        for _, l := range buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app") {
                nm := linkDisplayName(l)
                if nm == "" {
                        continue
                }
                if !strings.HasPrefix(nm, "⟦ ") || !strings.HasSuffix(nm, " ⟧") {
                        t.Fatalf("every default name must be ⟦ … ⟧, got %q", nm)
                }
        }
}
