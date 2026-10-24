package main

import (
        "encoding/base64"
        "encoding/json"
        "net/url"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

// ─────────── v3.20: ALPN hardening + short naming ───────────

func v320Setup(t *testing.T) {
        t.Helper()
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.Address = "138.199.37.231"
        state.LocalMode = &LocalModeState{Enabled: true}
        state.FrontSNI, state.FrontRand = "fonts.bunny.net", false
        state.FrontPicks = []FrontPick{
                {Base: "bunnycdn.com", IR: 1, At: 1792878993},
                {Base: "dash.bunny.net", IR: 1, At: 1792878993},
        }
        stateMu.Unlock()
}

// The v3.20 field bug: a tuning override of "h2,http/1.1" (a legit dropdown
// choice) used to ride EVERY link — and bunny's edge negotiates h2, killing
// the WS dial ("websocket: protocol h2 not supported"). Links must now force
// the safe per-transport value no matter what the tuning says.
func TestALPNForcedPerTransport(t *testing.T) {
        v320Setup(t)
        stateMu.Lock()
        state.Tuning = defaultTuning()
        state.Tuning.ALPN = "h2,http/1.1" // the poison setting
        stateMu.Unlock()
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        if len(links) == 0 {
                t.Fatal("no links rendered")
        }
        sawWS, sawHU, sawXHTTP, sawVMess, sawTrojan := false, false, false, false, false
        for _, l := range links {
                u := l.URL
                switch {
                case strings.HasPrefix(u, "vmess://"):
                        sawVMess = true
                        v := decodeVMess(t, u)
                        if v["alpn"] != "http/1.1" {
                                t.Errorf("vmess link must force alpn=http/1.1, got %v", v["alpn"])
                        }
                case strings.HasPrefix(u, "trojan://"):
                        sawTrojan = true
                        if s := paramOf(u, "alpn"); s != "http/1.1" {
                                t.Errorf("trojan link must force alpn=http/1.1, got %q", s)
                        }
                case strings.Contains(u, "type=ws&"):
                        sawWS = true
                        if s := paramOf(u, "alpn"); s != "http/1.1" {
                                t.Errorf("ws link must force alpn=http/1.1, got %q (%s)", s, first80(u))
                        }
                case strings.Contains(u, "type=httpupgrade&"):
                        sawHU = true
                        if s := paramOf(u, "alpn"); s != "http/1.1" {
                                t.Errorf("httpupgrade link must force alpn=http/1.1, got %q", s)
                        }
                case strings.Contains(u, "type=xhttp&"):
                        sawXHTTP = true
                        if s := paramOf(u, "alpn"); !strings.Contains(s, "h2") {
                                t.Errorf("xhttp link must carry h2, got %q", s)
                        }
                }
        }
        if !sawWS || !sawHU || !sawXHTTP || !sawVMess || !sawTrojan {
                t.Fatalf("expected all five transports, got ws=%v hu=%v xhttp=%v vmess=%v trojan=%v",
                        sawWS, sawHU, sawXHTTP, sawVMess, sawTrojan)
        }
        // unit level: the override only ever selects safe values
        if got := alpnForNet("ws", "h2,http/1.1"); got != "http/1.1" {
                t.Errorf("alpnForNet(ws, h2,http/1.1) = %q, want http/1.1", got)
        }
        if got := alpnForNet("xhttp", ""); got != "h2,http/1.1" {
                t.Errorf("alpnForNet(xhttp, \"\") = %q, want h2,http/1.1", got)
        }
        if got := alpnForNet("grpc", "http/1.1"); got != "h2" {
                t.Errorf("alpnForNet(grpc, …) = %q, want h2", got)
        }
}

// v3.20 short naming: "main-VLESS-WS 🥇" → "WS 🥇" — the client name and the
// protocol prefix are gone; transport + medal (and city) carry the row.
func TestShortDefaultNames(t *testing.T) {
        v320Setup(t)
        links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        var wsName, xhttpName, frontNameSeen, directName string
        for _, l := range links {
                nm := linkDisplayName(l)
                switch {
                case strings.Contains(l.URL, "type=ws&") && strings.Contains(l.URL, "alpn=") && wsName == "":
                        wsName = nm
                case strings.Contains(l.URL, "type=xhttp&") && xhttpName == "":
                        xhttpName = nm
                case strings.Contains(nm, "🛡️"):
                        directName = nm
                case strings.Contains(nm, "🎭"):
                        frontNameSeen = nm
                }
        }
        if !strings.HasPrefix(wsName, "WS ") || strings.Contains(wsName, "main-") || strings.Contains(wsName, "VLESS-WS") {
                t.Errorf("ws name should be short \"WS …\", got %q", wsName)
        }
        if !strings.HasPrefix(xhttpName, "XHTTP ") {
                t.Errorf("xhttp name should be short \"XHTTP …\", got %q", xhttpName)
        }
        if frontNameSeen != "" && strings.Contains(frontNameSeen, ".com") {
                t.Errorf("🎭 variant name should drop the registrar suffix, got %q", frontNameSeen)
        }
        if directName != "" && (strings.Contains(directName, "main-") || strings.Contains(directName, "VLESS-WS")) {
                t.Errorf("🛡️ name should be short, got %q", directName)
        }
        // a fully custom template still wins over the default
        stateMu.Lock()
        state.CfgFmt = "{name}/{net}"
        stateMu.Unlock()
        links = buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
        if len(links) > 0 {
                nm := linkDisplayName(links[0])
                if !strings.Contains(nm, "/") {
                        t.Errorf("custom template not honored, got %q", nm)
                }
        }
}

// States saved by pre-3.20 builds carry the old "{name}-{label}" default —
// loadState migrates them to the new short default.
func TestCfgFmtMigrationOnLoad(t *testing.T) {
        dir := t.TempDir()
        t.Setenv("DATA_DIR", dir)
        st := map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "cfg_fmt": "{name}-{label}"}
        b, _ := json.Marshal(st)
        if err := os.WriteFile(filepath.Join(dir, "state.json"), b, 0o600); err != nil {
                t.Fatal(err)
        }
        loadState()
        stateMu.RLock()
        fmtv := state.CfgFmt
        stateMu.RUnlock()
        if fmtv != "{label}" {
                t.Errorf("old default must migrate to {label}, got %q", fmtv)
        }
}

func paramOf(u, key string) string {
        i := strings.Index(u, "?")
        if i < 0 {
                return ""
        }
        for _, kv := range strings.Split(u[i+1:], "&") {
                if strings.HasPrefix(kv, key+"=") {
                        if d, err := url.QueryUnescape(kv[len(key)+1:]); err == nil {
                                return d
                        }
                        return kv[len(key)+1:]
                }
        }
        return ""
}

func decodeVMess(t *testing.T, u string) map[string]any {
        t.Helper()
        b, err := base64.StdEncoding.DecodeString(u[8:])
        if err != nil {
                t.Fatalf("bad vmess base64: %v", err)
        }
        v := map[string]any{}
        if err := json.Unmarshal(b, &v); err != nil {
                t.Fatalf("bad vmess json: %v", err)
        }
        return v
}
