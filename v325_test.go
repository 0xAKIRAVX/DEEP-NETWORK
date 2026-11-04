package main

// ─────────── v3.25 tests: bare-IP gate + Reality SNI variants ───────────
//
// The bug report: «کانفیگ‌ها اصلا وارد v2ray نمیشن و کار نمیکنن منفی یک
// میدن» — on a bare-IP VPS the subscription used to carry the CDN transport
// links (vless-ws / vless-hu / vmess-ws / trojan-ws). Those links hardcode
// port 443 + security=tls because a TLS-terminating CDN sits in front on the
// platform deployment — on a bare VPS nothing serves TLS on 443, so every
// one of them is a guaranteed -1 row in v2rayNG. v3.25 gates the CDN family
// out whenever the deployment host is a PUBLIC IP literal and ships the
// Reality link (+ SNI variants) instead.

import (
        "encoding/json"
        "strings"
        "testing"
)

func v325Setup(t *testing.T, host string) {
        t.Helper()
        t.Setenv("DATA_DIR", t.TempDir())
        t.Setenv("SECRET", "v325secret-for-tests")
        t.Setenv("UUID", "11111111-2222-3333-4444-555555555555")
        t.Setenv("TCP_HOST", host)
        t.Setenv("TCP_PORT", "443")
        t.Setenv("TCP_APP_PORT", "443")
        loadState()
        initReality()
        stateMu.Lock()
        state.Address = host
        state.RealitySNI = "www.microsoft.com"
        // ALL protocols enabled — this is exactly the legacy/migrated state an
        // old install carries; the gate must neutralize it on a bare IP anyway.
        state.Protocols = map[string]bool{}
        for _, k := range protoKeys {
                state.Protocols[k] = true
        }
        // deterministic geo for the address (no network in unit tests)
        state.TopEdges = []*EdgeScore{{IP: host, Med: 50, Loss: 0, City: "Frankfurt", CC: "DE", IRTLS: 1, IRTLSAt: 1792861085}}
        stateMu.Unlock()
}

func isCDNLink(u string) bool {
        return strings.Contains(u, "type=ws") || strings.Contains(u, "type=httpupgrade") ||
                strings.Contains(u, "type=xhttp") || strings.HasPrefix(u, "vmess://") ||
                strings.HasPrefix(u, "trojan://")
}

// The core regression: public-IP host → Reality-only sub even when every
// CDN protocol is (still) enabled in state.
func TestBareIPGateRealityOnly(t *testing.T) {
        v325Setup(t, "203.0.113.10")
        links := buildLinks(lmTestClient(), "203.0.113.10")
        if len(links) == 0 {
                t.Fatal("no links rendered")
        }
        reality, cdn := 0, 0
        for _, l := range links {
                if strings.Contains(l.URL, "security=reality") {
                        reality++
                }
                if isCDNLink(l.URL) {
                        cdn++
                        t.Errorf("CDN link rode the bare-IP sub: %s", first80(l.URL))
                }
        }
        if reality == 0 {
                t.Fatal("reality link missing from the bare-IP sub")
        }
        if reality != 3 { // primary + 2 SNI variants
                t.Errorf("reality rows = %d, want 3 (primary + 2 SNI variants)", reality)
        }
}

// Loopback/private hosts keep the legacy full list (local & test setups).
func TestBareIPGateSkipsLocalAndPrivate(t *testing.T) {
        v325Setup(t, "138.199.37.231")
        for _, host := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.9", "172.16.5.5"} {
                links := buildLinks(lmTestClient(), host)
                sawCDN := false
                for _, l := range links {
                        if isCDNLink(l.URL) {
                                sawCDN = true
                                break
                        }
                }
                if !sawCDN {
                        t.Errorf("host %s: legacy CDN links vanished (private hosts keep them)", host)
                }
        }
}

// The xray JSON sub (?fmt=xray) must not ship dead CDN outbounds on a VPS.
func TestClientConfigJSONBareIP(t *testing.T) {
        v325Setup(t, "203.0.113.10")
        cfg := clientConfigJSON(lmTestClient(), "203.0.113.10", "")
        if _, hasErr := cfg["error"]; hasErr {
                t.Fatalf("config error: %v", cfg["error"])
        }
        outs, _ := cfg["outbounds"].([]map[string]any)
        reality, cdn := 0, 0
        for _, ob := range outs {
                st, _ := ob["streamSettings"].(map[string]any)
                if st != nil && st["security"] == "reality" {
                        reality++
                }
                net_, _ := st["network"].(string)
                if st != nil && st["security"] == "tls" && (net_ == "ws" || net_ == "httpupgrade" || net_ == "xhttp") {
                        cdn++
                        t.Errorf("dead CDN outbound in bare-IP xray config (network=%s)", net_)
                }
        }
        if reality != 1 {
                t.Errorf("reality outbounds = %d, want 1", reality)
        }
        if cdn != 0 {
                t.Errorf("cdn outbounds = %d, want 0", cdn)
        }
}

// The server inbound must accept every SNI the sub ships variants for.
func TestServerNamesCarryAlternates(t *testing.T) {
        v325Setup(t, "203.0.113.10")
        conf := buildXrayConfig()
        inb, _ := conf["inbounds"].([]map[string]any)
        var names []string
        var dest string
        for _, ib := range inb {
                if ib["tag"] != "vless-reality" {
                        continue
                }
                st, _ := ib["streamSettings"].(map[string]any)
                rs, _ := st["realitySettings"].(map[string]any)
                for _, n := range rs["serverNames"].([]string) {
                        names = append(names, n)
                }
                dest = rs["dest"].(string)
        }
        if len(names) == 0 {
                t.Fatal("vless-reality inbound missing")
        }
        if names[0] != "www.microsoft.com" || dest != "www.microsoft.com:443" {
                t.Errorf("primary SNI/dest = %q / %q", names[0], dest)
        }
        joined := strings.Join(names, ",")
        for _, want := range realityAltSNIs("www.microsoft.com") {
                if !strings.Contains(joined, want) {
                        t.Errorf("serverNames missing alternate %q (have %q)", want, joined)
                }
        }
        // every SNI variant link the sub ships must be accepted by the inbound
        for _, l := range buildLinks(lmTestClient(), "203.0.113.10") {
                if !strings.Contains(l.URL, "security=reality") {
                        continue
                }
                sni := paramFromLink(t, l.URL, "sni")
                if !strings.Contains(joined, sni) {
                        t.Errorf("sub ships sni=%q but serverNames = %q", sni, joined)
                }
        }
}

func paramFromLink(t *testing.T, u, key string) string {
        t.Helper()
        q := u[strings.Index(u, "?")+1:]
        frag := strings.Index(q, "#")
        if frag >= 0 {
                q = q[:frag]
        }
        for _, kv := range strings.Split(q, "&") {
                if strings.HasPrefix(kv, key+"=") {
                        return kv[len(key)+1:]
                }
        }
        t.Fatalf("param %s not in %s", key, first80(u))
        return ""
}

// Alternates exclude the primary and stay capped at two.
func TestRealityAltSNIsDedup(t *testing.T) {
        alts := realityAltSNIs("www.microsoft.com")
        if len(alts) != 2 {
                t.Fatalf("alts = %v, want 2", alts)
        }
        for _, a := range realityAltSNIs("www.bing.com") {
                if a == "www.bing.com" {
                        t.Error("primary leaked into alternates")
                }
        }
        if got := sniShortLabel("www.bing.com"); got != "BING" {
                t.Errorf("sniShortLabel = %q", got)
        }
}

// The doctor's reality client config must mirror the shipped link (same
// pbk/sid/sni/flow) so the self-test proves what users actually receive.
func TestDoctorRealityConfigMirrorsLink(t *testing.T) {
        v325Setup(t, "203.0.113.10")
        cfg := doctorRealityConfig(lmTestClient(), 21099)
        b, err := json.Marshal(cfg)
        if err != nil {
                t.Fatal(err)
        }
        s := string(b)
        link := ""
        for _, l := range buildLinks(lmTestClient(), "203.0.113.10") {
                if strings.Contains(l.URL, "security=reality") {
                        link = l.URL
                        break
                }
        }
        if link == "" {
                t.Fatal("no reality link")
        }
        for _, want := range []string{realityPub, realitySID, "xtls-rprx-vision", paramFromLink(t, link, "sni")} {
                if !strings.Contains(s, want) {
                        t.Errorf("doctor reality config missing %q", first80(want))
                }
        }
}
