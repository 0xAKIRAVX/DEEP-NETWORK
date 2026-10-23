package main

import (
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

// ─────────── v3.7 speed pack + IPv6 ───────────

func TestBracketV6(t *testing.T) {
        cases := map[string]string{
                "2400:52e0:1500::714:1":     "[2400:52e0:1500::714:1]",
                "[2400:52e0:1500::714:1]":   "[2400:52e0:1500::714:1]",
                "1.2.3.4":                   "1.2.3.4",
                "deep-network.lucity.app":   "deep-network.lucity.app",
        }
        for in, want := range cases {
                if got := bracketV6(in); got != want {
                        t.Errorf("bracketV6(%q) = %q, want %q", in, got, want)
                }
        }
}

func TestMuxPayload(t *testing.T) {
        on := muxPayload(true)
        if on["enabled"] != true || on["concurrency"] != 8 || on["xudpConcurrency"] != 8 {
                t.Errorf("muxPayload(true) = %v", on)
        }
        off := muxPayload(false)
        if off["enabled"] != false || off["concurrency"] != -1 {
                t.Errorf("muxPayload(false) = %v", off)
        }
}

func TestValidAddress(t *testing.T) {
        good := []string{"185.59.222.196", "2400:52e0:1500::714:1", "[2400:52e0:1500::714:1]", "deep-network-development-w4a86.lucity.app"}
        bad := []string{"", "192.168.1.1", "10.0.0.1", "127.0.0.1", "fe80::1", "::1", "bad host!", "http://x.y"}
        for _, s := range good {
                if !validAddress(s) {
                        t.Errorf("validAddress(%q) should be true", s)
                }
        }
        for _, s := range bad {
                if validAddress(s) {
                        t.Errorf("validAddress(%q) should be false", s)
                }
        }
}

func TestMergeTuningMuxOff(t *testing.T) {
        base := defaultTuning()
        if base.MuxOff {
                t.Fatal("default tuning must have mux ON (MuxOff=false)")
        }
        out := mergeTuning(base, map[string]any{"mux_off": true})
        if !out.MuxOff {
                t.Errorf("mergeTuning should honor mux_off=true")
        }
        out2 := mergeTuning(out, map[string]any{"mux_off": false})
        if out2.MuxOff {
                t.Errorf("mergeTuning should honor mux_off=false")
        }
}

// speedPackServer boots the panel with a fixed state (mux on, v6 address).
func speedPackServer(t *testing.T) *httptest.Server {
        t.Helper()
        t.Setenv("DATA_DIR", t.TempDir())
        loadState()
        stateMu.Lock()
        state.Address = "2400:52e0:1500::714:1"
        state.Tuning = defaultTuning()
        saveStateLocked()
        stateMu.Unlock()
        mux := http.NewServeMux()
        mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
                tok := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
                handleSub(w, r, tok)
        })
        return httptest.NewServer(mux)
}

func subTokenForMain(t *testing.T) string {
        stateMu.RLock()
        defer stateMu.RUnlock()
        for _, c := range state.Clients {
                if c.ID == state.UUID {
                        return subToken(c.ID)
                }
        }
        return subToken(mainUUID())
}

func TestSubXrayHasMuxSpeedPack(t *testing.T) {
        srv := speedPackServer(t)
        defer srv.Close()
        resp, err := http.Get(srv.URL + "/sub/" + subTokenForMain(t) + "?fmt=xray")
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                t.Fatalf("status = %d", resp.StatusCode)
        }
        if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
                t.Errorf("content-type = %q", ct)
        }
        if ui := resp.Header.Get("Subscription-Userinfo"); !strings.Contains(ui, "upload=") {
                t.Errorf("missing Subscription-Userinfo: %q", ui)
        }
        var cfg map[string]any
        if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
                t.Fatal(err)
        }
        outs, _ := cfg["outbounds"].([]any)
        if len(outs) == 0 {
                t.Fatal("no outbounds")
        }
        muxFound, muxOn := 0, 0
        for _, o := range outs {
                ob, _ := o.(map[string]any)
                m, _ := ob["mux"].(map[string]any)
                if m == nil {
                        continue
                }
                muxFound++
                if m["enabled"] == true && m["concurrency"] == float64(8) {
                        muxOn++
                }
        }
        if muxFound == 0 {
                t.Fatal("no mux blocks in config")
        }
        if muxOn == 0 {
                t.Error("speed pack: no outbound has mux enabled (concurrency 8)")
        }
        // every vnext address must be the bare v6 (no brackets in Xray JSON)
        for _, o := range outs {
                ob, _ := o.(map[string]any)
                st, _ := ob["settings"].(map[string]any)
                if st == nil {
                        continue
                }
                if vn, ok := st["vnext"].([]any); ok && len(vn) > 0 {
                        v, _ := vn[0].(map[string]any)
                        if v["address"] != "2400:52e0:1500::714:1" {
                                t.Errorf("vnext address = %v, want bare IPv6", v["address"])
                        }
                }
        }
}

func TestSubXrayMuxOffRespected(t *testing.T) {
        srv := speedPackServer(t)
        defer srv.Close()
        stateMu.Lock()
        state.Tuning = mergeTuning(state.Tuning, map[string]any{"mux_off": true})
        saveStateLocked()
        stateMu.Unlock()
        resp, err := http.Get(srv.URL + "/sub/" + subTokenForMain(t) + "?fmt=xray")
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        var cfg map[string]any
        if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
                t.Fatal(err)
        }
        for _, o := range cfg["outbounds"].([]any) {
                ob, _ := o.(map[string]any)
                if m, _ := ob["mux"].(map[string]any); m != nil && m["enabled"] == true {
                        t.Error("mux_off=true must disable mux everywhere")
                }
        }
}

func TestSubJSONArrayAndDefault(t *testing.T) {
        srv := speedPackServer(t)
        defer srv.Close()
        tok := subTokenForMain(t)

        // ?fmt=json → array of {name,url}
        resp, err := http.Get(srv.URL + "/sub/" + tok + "?fmt=json")
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        var arr []map[string]string
        if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
                t.Fatalf("fmt=json: %v", err)
        }
        if len(arr) == 0 {
                t.Fatal("fmt=json returned an empty array")
        }
        for _, e := range arr {
                if e["url"] == "" || e["name"] == "" {
                        t.Errorf("fmt=json entry incomplete: %v", e)
                }
        }

        // default → base64 body with at least one link
        resp2, err := http.Get(srv.URL + "/sub/" + tok)
        if err != nil {
                t.Fatal(err)
        }
        defer resp2.Body.Close()
        body := make([]byte, 64)
        n, _ := resp2.Body.Read(body)
        if n == 0 {
                t.Fatal("empty default sub")
        }
}

func TestLinksWithV6AddressBrackets(t *testing.T) {
        srv := speedPackServer(t)
        defer srv.Close()
        stateMu.RLock()
        c := state.Clients[0]
        stateMu.RUnlock()
        links := buildLinks(c, "deep-network-development-w4a86.lucity.app")
        if len(links) == 0 {
                t.Fatal("no links generated")
        }
        for _, l := range links {
                if strings.HasPrefix(l.URL, "vmess://") {
                        continue // vmess JSON keeps the bare address in "add"
                }
                if strings.Contains(l.URL, "@2400:") {
                        t.Errorf("v6 URI not bracketed: %s", first80(l.URL))
                }
                if strings.Contains(l.URL, "@[2400:52e0:1500::714:1]") {
                        // good — bracketed
                        return
                }
        }
        t.Error("no link carried the bracketed IPv6 address")
}

func first80(s string) string {
        if len(s) > 80 {
                return s[:80] + "…"
        }
        return s
}
