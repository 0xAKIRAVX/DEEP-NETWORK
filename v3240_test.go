package main

// v3.24 tests: VPS direct mode — the "sub links don't work / everything -1"
// fix. On a bare VPS there is no TLS-terminating CDN: port 443 is the
// Reality inbound, the panel rides plain HTTP on PORT. The link set, the
// sub URL scheme and the full-client config must all reflect that shape.

import (
        "encoding/base64"
        "io"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "testing"
)

func v324Setup(t *testing.T, domain string) {
        t.Helper()
        t.Setenv("DEPLOY_MODE", "vps")
        t.Setenv("DATA_DIR", t.TempDir())
        if domain != "" {
                t.Setenv("DOMAIN", domain)
        }
        loadState()
        initReality() // derive the x25519 pair so the Reality rows actually emit
        stateMu.Lock()
        state.Address = ""
        state.Tuning = defaultTuning()
        state.LocalMode = nil
        if len(state.Clients) == 0 {
                state.Clients = []*Client{{Name: "main", ID: mainUUID()}}
        }
        stateMu.Unlock()
}

func TestVpsModeDetection(t *testing.T) {
        // explicit env wins both ways
        t.Setenv("DOMAIN", "deep-network-development-w4a86.lucity.app")
        if vpsMode() {
                t.Errorf("lucity DOMAIN must not be VPS mode")
        }
        t.Setenv("DEPLOY_MODE", "vps")
        if !vpsMode() {
                t.Errorf("DEPLOY_MODE=vps must force VPS mode")
        }
        t.Setenv("DEPLOY_MODE", "cdn")
        t.Setenv("DOMAIN", "1.2.3.4")
        if vpsMode() {
                t.Errorf("DEPLOY_MODE=cdn must win over an IP DOMAIN")
        }
        os.Unsetenv("DEPLOY_MODE")
        t.Setenv("DOMAIN", "203.0.113.7")
        if !vpsMode() {
                t.Errorf("an IP-literal DOMAIN means VPS mode")
        }
        t.Setenv("DOMAIN", "")
        if !vpsMode() {
                t.Errorf("no DOMAIN means VPS mode")
        }
        os.Unsetenv("DOMAIN")
}

func TestVpsRealityAddrFallbacks(t *testing.T) {
        t.Setenv("DEPLOY_MODE", "vps")
        t.Setenv("TCP_HOST", "")
        t.Setenv("TCP_PORT", "")
        t.Setenv("TCP_APP_PORT", "")
        t.Setenv("DOMAIN", "203.0.113.7")
        if got := vpsRealityAddr(); got != "203.0.113.7" {
                t.Errorf("addr fallback: got %q, want the DOMAIN IP", got)
        }
        if got := vpsRealityPort(); got != 443 {
                t.Errorf("port fallback: got %d, want 443", got)
        }
        t.Setenv("TCP_HOST", "198.51.100.9")
        t.Setenv("TCP_PORT", "8443")
        t.Setenv("TCP_APP_PORT", "8443")
        if got := vpsRealityAddr(); got != "198.51.100.9" {
                t.Errorf("TCP_HOST must win: got %q", got)
        }
        if got := vpsRealityPort(); got != 8443 {
                t.Errorf("TCP_PORT must win: got %d", got)
        }
}

func TestVpsLinksRealityFirstNoTLSRows(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("TCP_APP_PORT", "443")
        t.Setenv("PORT", "80")

        links := buildLinks(&Client{Name: "main", ID: mainUUID()}, "203.0.113.7")
        if len(links) == 0 {
                t.Fatal("VPS link set is empty")
        }
        if links[0].Key != "vless-reality" {
                t.Fatalf("Reality must be the FIRST row (v2rayNG tests top-down), got %q: %s", links[0].Key, links[0].URL)
        }
        u := links[0].URL
        for _, want := range []string{"security=reality", "flow=xtls-rprx-vision", "pbk=", "sid=", "spx=%2F", "@203.0.113.7:443"} {
                if !strings.Contains(u, want) {
                        t.Errorf("reality link missing %q: %s", want, u)
                }
        }
        for _, l := range links {
                if strings.Contains(l.URL, "security=tls") {
                        t.Errorf("VPS sub must carry no TLS rows (nothing serves TLS on 443): %s", l.URL)
                }
        }
        // plain ws fallback on the panel port
        var ws bool
        for _, l := range links {
                if l.Key == "vless-ws-plain" {
                        ws = true
                        if !strings.Contains(l.URL, "security=none") || !strings.Contains(l.URL, "@203.0.113.7:80") {
                                t.Errorf("plain ws fallback must ride the panel port with security=none: %s", l.URL)
                        }
                }
        }
        if !ws {
                t.Errorf("plain ws fallback row missing")
        }
        // vmess plain: base64 must decode and carry tls:""
        for _, l := range links {
                if strings.HasPrefix(l.URL, "vmess://") {
                        b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(l.URL, "vmess://"))
                        if err != nil {
                                t.Fatalf("vmess link not base64: %v", err)
                        }
                        if !strings.Contains(string(b), `"tls":""`) {
                                t.Errorf("vmess plain link must carry tls:\"\": %s", b)
                        }
                }
        }
}

func TestVpsSubURLSchemeAndPort(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("PORT", "8080")

        r := httptest.NewRequest("GET", "http://203.0.113.7:8080/panel/api/state", nil)
        pl := statePayload(r)
        users, _ := pl["clients"].([]map[string]any)
        if len(users) == 0 {
                t.Fatal("state payload has no clients")
        }
        sub, _ := users[0]["sub_url"].(string)
        if !strings.HasPrefix(sub, "http://203.0.113.7:8080/sub/") {
                t.Errorf("VPS sub_url must be http + carry the public port, got %q", sub)
        }
}

func TestVpsSubServesRealityFirst(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("PORT", "80")

        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if strings.HasPrefix(r.URL.Path, "/sub/") {
                        handleSub(w, r, strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/"))
                        return
                }
                http.NotFound(w, r)
        }))
        defer srv.Close()

        resp, err := http.Get(srv.URL + "/sub/" + subTokenForMain(t))
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        b, _ := io.ReadAll(resp.Body)
        dec, err := base64.StdEncoding.DecodeString(string(b))
        if err != nil {
                t.Fatalf("sub body is not base64: %v", err)
        }
        lines := strings.Split(strings.TrimSpace(string(dec)), "\n")
        if len(lines) == 0 || lines[0] == "" {
                t.Fatal("empty sub")
        }
        if !strings.HasPrefix(lines[0], "vless://") || !strings.Contains(lines[0], "security=reality") {
                t.Errorf("first sub row must be the Reality link, got %q", lines[0])
        }
}

func TestVpsXrayConfigShape(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("PORT", "80")

        cfg := clientConfigJSON(&Client{Name: "main", ID: mainUUID()}, "203.0.113.7", "")
        if _, hasErr := cfg["error"]; hasErr {
                t.Fatalf("config error: %v", cfg["error"])
        }
        obs, _ := cfg["outbounds"].([]map[string]any)
        if len(obs) == 0 {
                t.Fatal("no outbounds")
        }
        first, _ := obs[0]["tag"].(string)
        if first != "proxy" {
                t.Fatalf("first outbound must be the Reality proxy, got %q", first)
        }
        ss, _ := obs[0]["streamSettings"].(map[string]any)
        if ss["security"] != "reality" {
                t.Errorf("first outbound must be Reality, got %v", ss["security"])
        }
        mux, _ := obs[0]["mux"].(map[string]any)
        if en, _ := mux["enabled"].(bool); en {
                t.Errorf("Reality outbound must ship mux OFF (Vision + mux kills throughput)")
        }
        // ws fallback rides the panel port, plain
        var wsPlain bool
        for _, o := range obs {
                st, _ := o["streamSettings"].(map[string]any)
                if st != nil && st["security"] == "none" {
                        set, _ := o["settings"].(map[string]any)
                        vnext, _ := set["vnext"].([]map[string]any)
                        if len(vnext) > 0 {
                                if p, _ := vnext[0]["port"].(int); p == 80 {
                                        wsPlain = true
                                }
                        }
                }
        }
        if !wsPlain {
                t.Errorf("no plain ws fallback on the panel port in the xray config")
        }
}

func TestVpsOperatorProfileParam(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("PORT", "80")

        // mci profile must not error and keeps Reality first
        cfg := clientConfigJSON(&Client{Name: "main", ID: mainUUID()}, "203.0.113.7", "mci")
        if _, hasErr := cfg["error"]; hasErr {
                t.Fatalf("profile=mci config error: %v", cfg["error"])
        }
        obs, _ := cfg["outbounds"].([]map[string]any)
        tag, _ := obs[0]["tag"].(string)
        if tag != "proxy" {
                t.Errorf("profile configs must keep Reality first, got %q", tag)
        }
}

func TestVpsBannerShowsCredentials(t *testing.T) {
        v324Setup(t, "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("PORT", "8080")
        t.Setenv("NO_COLOR", "1")

        stateMu.Lock()
        state.AdminUser = "admin"
        state.AdminPass = "S3cret-Pass"
        stateMu.Unlock()

        // capture stdout
        old := os.Stdout
        r, w, _ := os.Pipe()
        os.Stdout = w
        bootBanner()
        w.Close()
        os.Stdout = old
        out, _ := io.ReadAll(r)
        s := string(out)

        for _, want := range []string{"DEEP NETWORK", "PASSWORD", "S3cret-Pass", "admin",
                "http://203.0.113.7:8080/panel", "/sub/"} {
                if !strings.Contains(s, want) {
                        t.Errorf("banner missing %q\nbanner:\n%s", want, s)
                }
        }
        if strings.Contains(s, "\033[") {
                t.Errorf("NO_COLOR must strip ANSI codes from the banner")
        }
}
