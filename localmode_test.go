package main

import (
        "encoding/base64"
        "encoding/json"
        "io"
        "net/http"
        "net/http/httptest"
        "strings"
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
        if len(links) < 5 {
                t.Fatalf("expected >=5 local variants (direct + white-SNI + relay×3), got %d", len(links))
        }
        var haveRelay, haveDirect, haveWhite bool
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
                case "vless-ws-whitesni":
                        haveWhite = true
                        if !strings.Contains(l.URL, "sni=www.arvancloud.ir") {
                                t.Errorf("white-SNI link must carry the whitelisted SNI — %s", l.URL)
                        }
                        if !strings.Contains(l.URL, "allowInsecure=1") {
                                t.Errorf("white-SNI link MUST set allowInsecure=1 (cert will mismatch) — %s", l.URL)
                        }
                        if !strings.Contains(l.URL, "host=deep-network-development-w4a86.lucity.app") {
                                t.Errorf("white-SNI routing Host must remain the real panel host — %s", l.URL)
                        }
                case "vless-hu-relay", "trojan-ws-relay":
                        if !strings.Contains(l.URL, "79.175.129.200:2053") {
                                t.Errorf("%s must carry relay addr:port — %s", l.Key, l.URL)
                        }
                }
        }
        if !haveRelay || !haveDirect || !haveWhite {
                t.Fatalf("missing variants: relay=%v direct=%v white=%v (links=%d)", haveRelay, haveDirect, haveWhite, len(links))
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

// v3.13: the payload must carry the SNI quick-picks and a real count of
// DNS-free routes; the kit must document the no-KYC reality honestly.
func TestPayloadCarriesSniPicksAndDirectRoutes(t *testing.T) {
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.LocalMode = &LocalModeState{Enabled: true, FakeSNI: "www.aparat.com"}
        state.Tuning = defaultTuning()
        stateMu.Unlock()
        p := localModePayload("deep-network-development-w4a86.lucity.app")
        picks, _ := p["sni_picks"].([]string)
        if len(picks) < 3 || !containsStr(picks, "www.arvancloud.ir") {
                t.Fatalf("sni_picks missing/short: %v", picks)
        }
        if dr, _ := p["direct_routes"].(int); dr < 1 {
                t.Fatalf("direct_routes must count at least the origin direct-IP variant, got %v", p["direct_routes"])
        }
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
                "کیت بقا برای شبکه ملی", "🇮🇷", "socat", "systemd", "iptables", "CDN ایرانی", "arvancloud.ir", "بدون ثبت هویت و بدون دامنه",
                "79.175.129.200:443", "185.59.222.196:443", "آبان ۹۸",
        } {
                if !strings.Contains(kit, want) {
                        t.Errorf("kit text missing %q", want)
                }
        }
}
