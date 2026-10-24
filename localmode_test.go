package main

import (
        "encoding/base64"
        "encoding/json"
        "io"
        "net/http"
        "net/http/httptest"
        "strings"
        "time"
        "testing"
)

// ─────────── v3.11: national-internet kit ───────────

func TestLocalModeSanitize(t *testing.T) {
        good := localModeSanitize(&LocalModeState{
                Enabled: true, RelayHost: " 79.175.129.200 ", RelayPort: 8443,
                FakeSNI: "WWW.Arvancloud.IR ", DirectIP: "185.59.222.196",
        })
        if !good.Enabled || good.RelayHost != "79.175.129.200" || good.RelayPort != 8443 ||
                good.FakeSNI != "www.arvancloud.ir" || good.DirectIP != "185.59.222.196" {
                t.Fatalf("sanitize mangled valid input: %+v", good)
        }
        // bad values are dropped, port falls back to 443
        bad := localModeSanitize(&LocalModeState{
                Enabled: true, RelayHost: "192.168.1.5", RelayPort: 99999,
                FakeSNI: "bad host!", DirectIP: "not-an-ip",
        })
        if bad.RelayHost != "" || bad.RelayPort != 443 || bad.FakeSNI != "" || bad.DirectIP != "" {
                t.Fatalf("sanitize kept invalid values: %+v", bad)
        }
        if nilValue := localModeSanitize(nil); nilValue.Enabled || nilValue.RelayPort != 0 {
                t.Fatalf("sanitize(nil) should be zero value: %+v", nilValue)
        }
}

func lmTestClient() *Client {
        return &Client{Name: "main", ID: "11111111-2222-3333-4444-555555555555"}
}

func TestBuildLocalLinksDisabled(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: false, RelayHost: "79.175.129.200"}
        stateMu.Unlock()
        if links := buildLocalLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app"); links != nil {
                t.Fatalf("disabled kit must produce no links, got %d", len(links))
        }
}

func TestBuildLocalLinksRelayAndVariants(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{
                Enabled: true, RelayHost: "79.175.129.200", RelayPort: 2053,
                FakeSNI: "www.arvancloud.ir", DirectIP: "185.59.222.196",
        }
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        const host = "deep-network-development-w4a86.lucity.app"
        links := buildLocalLinks(lmTestClient(), host)
        if len(links) < 4 {
                t.Fatalf("expected >=4 local variants (direct + relay×3), got %d", len(links))
        }
        var haveRelay, haveDirect bool
        for _, l := range links {
                switch l.Key {
                case "vless-ws-relay":
                        haveRelay = true
                        if !strings.Contains(l.URL, "79.175.129.200:2053") {
                                t.Errorf("relay link must carry relay addr:port — %s", l.URL)
                        }
                        // TLS is END-TO-END with the panel: SNI/host must be the panel's,
                        // never the relay's own address.
                        if !strings.Contains(l.URL, "host=deep-network-development-w4a86.lucity.app") &&
                                !strings.Contains(l.URL, "host=ng") {
                                t.Errorf("relay WS host must stay the panel host — %s", l.URL)
                        }
                        if strings.Contains(l.URL, "allowInsecure=1") {
                                t.Errorf("relay link must NOT need allowInsecure (valid cert end-to-end) — %s", l.URL)
                        }
                case "vless-ws-direct":
                        haveDirect = true
                        if !strings.Contains(l.URL, "185.59.222.196:443") {
                                t.Errorf("direct link must carry the literal origin IP — %s", l.URL)
                        }
                        if strings.Contains(l.URL, "allowInsecure=1") {
                                t.Errorf("direct link must NOT need allowInsecure — %s", l.URL)
                        }
                case "vless-hu-relay", "trojan-ws-relay":
                        if !strings.Contains(l.URL, "79.175.129.200:2053") {
                                t.Errorf("%s must carry relay addr:port — %s", l.Key, l.URL)
                        }
                }
        }
        for _, l := range links { // v3.14: allowInsecure was removed from modern cores — no link may carry it
                if strings.Contains(l.URL, "allowInsecure=1") {
                        t.Errorf("no variant may ship allowInsecure=1 (modern xray cores reject it) — %s", l.URL)
                }
        }
        if !haveRelay || !haveDirect {
                t.Fatalf("missing variants: relay=%v direct=%v (links=%d)", haveRelay, haveDirect, len(links))
        }
}

func TestBuildLocalLinksRespectsUserProtocols(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "79.175.129.200"}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        c := lmTestClient()
        c.Protocols = []string{"trojan-ws"} // ONLY trojan for this user
        links := buildLocalLinks(c, "deep-network-development-w4a86.lucity.app")
        for _, l := range links {
                if strings.HasPrefix(l.URL, "vless://") {
                        t.Errorf("user restricted to trojan must not receive vless relay links — %s", l.URL)
                }
        }
        if len(links) != 1 {
                t.Fatalf("expected exactly the trojan relay variant, got %d", len(links))
        }
}

func TestBuildLinksAppendsLocalVariants(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.Tuning = defaultTuning()
        state.LocalMode = &LocalModeState{}
        saveStateLocked()
        stateMu.Unlock()
        const host = "deep-network-development-w4a86.lucity.app"
        c := lmTestClient()
        base := len(buildLinks(c, host))

        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "79.175.129.200", RelayPort: 443, DirectIP: "185.59.222.196"}
        saveStateLocked()
        stateMu.Unlock()
        withKit := buildLinks(c, host)
        if len(withKit) <= base {
                t.Fatalf("kit must append variants: base=%d withKit=%d", base, len(withKit))
        }
        var relaySeen bool
        for _, l := range withKit {
                if l.Key == "vless-ws-relay" {
                        relaySeen = true
                }
        }
        if !relaySeen {
                t.Fatalf("vless-ws-relay missing from full link list")
        }
}

// subscription (base64) must carry the survival variants so client apps
// can auto-failover to the relay when international access is cut.
func TestSubCarriesSurvivalVariants(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "79.175.129.200", RelayPort: 443, DirectIP: "185.59.222.196"}
        state.Tuning = defaultTuning()
        saveStateLocked()
        stateMu.Unlock()
        c := lmTestClient()
        stateMu.Lock()
        state.Clients = []*Client{c}
        stateMu.Unlock()
        mux := http.NewServeMux()
        mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
                handleSub(w, r, strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/"))
        })
        srv := httptest.NewServer(mux)
        defer srv.Close()
        resp, err := http.Get(srv.URL + "/sub/" + subToken(c.ID))
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                t.Fatalf("sub status = %d", resp.StatusCode)
        }
        raw, err := io.ReadAll(resp.Body)
        if err != nil {
                t.Fatal(err)
        }
        decoded, err := base64.StdEncoding.DecodeString(string(raw))
        if err != nil {
                t.Fatal(err)
        }
        body := string(decoded)
        if !strings.Contains(body, "79.175.129.200:443") {
                t.Errorf("subscription must contain the relay endpoint")
        }
        if !strings.Contains(body, "185.59.222.196:443") {
                t.Errorf("subscription must contain the direct endpoint")
        }
        if !strings.Contains(body, "%F0%9F%87%AE%F0%9F%87%B7") && !strings.Contains(body, "🇮🇷") {
                t.Errorf("relay links must be labelled with the 🇮🇷 marker")
        }
        if strings.Contains(body, "allowInsecure=1") {
                t.Errorf("subscription must not carry allowInsecure (removed from modern cores)")
        }
}

func TestLocalModeSettingsRoundTrip(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.URL.Path == "/panel/api/settings" {
                        handleSettings(w, r)
                        return
                }
                if r.URL.Path == "/panel/api/localmode" {
                        sendJSONGz(r, w, 200, localModePayload(requestHost(r)))
                        return
                }
                sendJSON(w, 404, map[string]any{"error": "not found"})
        }))
        defer srv.Close()

        body := `{"local_mode":{"enabled":true,"relay_host":"79.175.129.200","relay_port":2053,"fake_sni":"www.arvancloud.ir","direct_ip":"185.59.222.196"}}`
        resp, err := http.Post(srv.URL+"/panel/api/settings", "application/json", strings.NewReader(body))
        if err != nil || resp.StatusCode != 200 {
                t.Fatalf("settings save failed: %v %s", err, resp.Status)
        }
        resp.Body.Close()

        resp2, err := http.Get(srv.URL + "/panel/api/localmode")
        if err != nil {
                t.Fatal(err)
        }
        defer resp2.Body.Close()
        var out map[string]any
        if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
                t.Fatal(err)
        }
        if out["enabled"] != true || out["relay_host"] != "79.175.129.200" ||
                out["fake_sni"] != "www.arvancloud.ir" || out["direct_ip"] != "185.59.222.196" {
                t.Fatalf("round-trip mismatch: %+v", out)
        }
        if out["relay_port"].(float64) != 2053 {
                t.Fatalf("relay_port mismatch: %v", out["relay_port"])
        }
        g := out["guide"].(map[string]any)
        if !strings.Contains(g["socat"].(string), "socat TCP-LISTEN:443") {
                t.Errorf("socat guide missing/invalid: %v", g["socat"])
        }
        if !strings.Contains(g["docker"].(string), "alpine/socat") {
                t.Errorf("docker guide missing/invalid: %v", g["docker"])
        }
}

// v3.12: a DOMAIN relay emits BOTH the dumb-relay variants (sni=panel) and
// the Iranian-CDN-front variants (sni=host=domain, port 443); an IP relay
// emits relay-only (a CDN cannot be an IP literal).
func TestCDNFrontVariantsForDomainRelay(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "net.myrelay.ir", RelayPort: 8443}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        links := buildLocalLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        keys := map[string]Link{}
        for _, l := range links {
                keys[l.Key] = l
        }
        for _, k := range []string{"vless-ws-relay", "vless-hu-relay", "trojan-ws-relay",
                "vless-ws-cdn", "vless-hu-cdn", "trojan-ws-cdn"} {
                if _, ok := keys[k]; !ok {
                        t.Fatalf("domain relay missing variant %q (have %v)", k, keys)
                }
        }
        cdn := keys["vless-ws-cdn"].URL
        if !strings.Contains(cdn, "@net.myrelay.ir:443") {
                t.Errorf("CDN variant must connect to the CDN domain on 443: %s", cdn)
        }
        if !strings.Contains(cdn, "sni=net.myrelay.ir") || !strings.Contains(cdn, "host=net.myrelay.ir") {
                t.Errorf("CDN variant must present the CDN domain as both sni and host: %s", cdn)
        }
        if strings.Contains(cdn, "allowInsecure=1") {
                t.Errorf("CDN variant must trust the CDN's valid certificate: %s", cdn)
        }
        // dumb relay keeps panel SNI + configured port
        relay := keys["vless-ws-relay"].URL
        if !strings.Contains(relay, "@net.myrelay.ir:8443") {
                t.Errorf("relay variant must use the configured relay port: %s", relay)
        }
        if !strings.Contains(relay, "host=deep-network-development-w4a86.lucity.app") {
                t.Errorf("relay variant must keep the panel host header: %s", relay)
        }
}

func TestNoCDNVariantsForIPRelay(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "79.175.129.200", RelayPort: 443}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        links := buildLocalLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        for _, l := range links {
                if strings.HasSuffix(l.Key, "-cdn") {
                        t.Errorf("IP relay must not emit CDN variants, got %q", l.Key)
                }
        }
        found := false
        for _, l := range links {
                if l.Key == "vless-ws-relay" {
                        found = true
                }
        }
        if !found {
                t.Fatalf("IP relay must still emit the dumb-relay variants")
        }
}

// v3.14: the payload must count DNS-free routes; with edges configured the
// count must grow (direct origin IP + graded edges).
func TestPayloadCountsDirectRoutes(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        base := localModePayload("deep-network-development-w4a86.lucity.app")
        dr0, _ := base["direct_routes"].(int)
        if dr0 < 1 {
                t.Fatalf("direct_routes must count at least the origin direct-IP variant, got %v", base["direct_routes"])
        }
        stateMu.Lock()
        state.TopEdges = []*EdgeScore{{IP: "185.180.12.68", Med: 40, Loss: 0, SpeedKbps: 90, Score: 42}}
        state.MultiEdge = true
        stateMu.Unlock()
        withEdges := localModePayload("deep-network-development-w4a86.lucity.app")
        dr1, _ := withEdges["direct_routes"].(int)
        if dr1 <= dr0 {
                t.Fatalf("edge set must add direct routes: base=%d withEdges=%d", dr0, dr1)
        }
}

// v3.14: auto-scan apply semantics — manual address survives, auto address is
// replaceable, TopEdges/MultiEdge always updated.
func TestApplyAutoEdges(t *testing.T) {
        now := time.Now()
        mk := func(ip string, med float64) *EdgeScore {
                return &EdgeScore{IP: ip, Med: med, Loss: 0, SpeedKbps: 80, Score: med}
        }
        t.Run("manual address survives", func(t *testing.T) {
                st := &State{Address: "1.2.3.4", AutoAddr: false}
                got := applyAutoEdges(st, []*EdgeScore{mk("9.9.9.9", 20), mk("8.8.8.8", 25)}, now)
                if got != "1.2.3.4" || st.Address != "1.2.3.4" || st.AutoAddr {
                        t.Fatalf("manual address must survive: got=%q addr=%q auto=%v", got, st.Address, st.AutoAddr)
                }
                if len(st.TopEdges) != 2 || !st.MultiEdge || st.AutoScanAt != now.Unix() {
                        t.Fatalf("edges/multi/at not applied: %+v", st)
                }
        })
        t.Run("auto address replaces", func(t *testing.T) {
                st := &State{Address: "1.2.3.4", AutoAddr: true}
                got := applyAutoEdges(st, []*EdgeScore{mk("9.9.9.9", 20)}, now)
                if got != "9.9.9.9" || !st.AutoAddr {
                        t.Fatalf("auto address must be replaceable: got=%q addr=%q", got, st.Address)
                }
        })
        t.Run("empty/domain address becomes best", func(t *testing.T) {
                st := &State{Address: ""}
                if got := applyAutoEdges(st, []*EdgeScore{mk("9.9.9.9", 20)}, now); got != "9.9.9.9" || !st.AutoAddr {
                        t.Fatalf("empty address must become best: got=%q", got)
                }
                st2 := &State{Address: "panel.example.com"}
                if got := applyAutoEdges(st2, []*EdgeScore{mk("9.9.9.9", 20)}, now); got != "9.9.9.9" {
                        t.Fatalf("domain address must become best: got=%q", got)
                }
        })
        t.Run("empty result is a no-op", func(t *testing.T) {
                st := &State{Address: "1.2.3.4", TopEdges: []*EdgeScore{mk("9.9.9.9", 20)}}
                applyAutoEdges(st, nil, now)
                if len(st.TopEdges) != 1 || st.Address != "1.2.3.4" {
                        t.Fatalf("empty scan must not wipe state")
                }
        })
}

func TestLocalModeKitText(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, RelayHost: "79.175.129.200", RelayPort: 443, DirectIP: "185.59.222.196"}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        kit := localModeKitText("deep-network-development-w4a86.lucity.app")
        for _, want := range []string{
                "کیت بقا برای شبکه ملی", "🇮🇷", "socat", "systemd", "iptables", "CDN ایرانی", "arvancloud.ir", "بدون ثبت هویت و بدون دامنه", "اسکن خودکار",
                "79.175.129.200:443", "185.59.222.196:443", "آبان ۹۸",
        } {
                if !strings.Contains(kit, want) {
                        t.Errorf("kit text missing %q", want)
                }
        }
}
