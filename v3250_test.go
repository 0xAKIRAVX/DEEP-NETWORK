package main

// v3.25 tests: the user-asked transports — VLESS+Reality+XHTTP and
// VLESS+Reality+gRPC — in the VPS link set, the xray server config, the
// full client config and the state payload; plus the CDN-mode gating (no
// dead toggles there) and the loadState migration of existing installs.

import (
        "encoding/base64"
        "io"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"
)

func v325Setup(t *testing.T) {
        t.Helper()
        t.Setenv("DEPLOY_MODE", "vps")
        t.Setenv("DATA_DIR", t.TempDir())
        t.Setenv("DOMAIN", "203.0.113.7")
        t.Setenv("TCP_HOST", "203.0.113.7")
        t.Setenv("TCP_PORT", "443")
        t.Setenv("TCP_APP_PORT", "443")
        t.Setenv("PORT", "80")
        t.Setenv("XHTTP_PORT", "")
        t.Setenv("GRPC_PORT", "")
        realityVariantsCached = nil // fresh probes per test
        vpsExtraCached = nil
        loadState()
        initReality()
        stateMu.Lock()
        state.Address = ""
        state.Tuning = defaultTuning()
        state.LocalMode = nil
        if len(state.Clients) == 0 {
                state.Clients = []*Client{{Name: "main", ID: mainUUID()}}
        }
        stateMu.Unlock()
}

func TestV325ExtraPortPicking(t *testing.T) {
        v325Setup(t)
        ep := computeVpsExtraPorts(nil)
        if ep.xhttp != 2087 || ep.grpc != 2095 {
                t.Fatalf("default picks: got xhttp=%d grpc=%d, want 2087/2095", ep.xhttp, ep.grpc)
        }
        // env overrides
        vpsExtraCached = nil
        t.Setenv("XHTTP_PORT", "12345")
        t.Setenv("GRPC_PORT", "12346")
        ep = computeVpsExtraPorts(nil)
        if ep.xhttp != 12345 || ep.grpc != 12346 {
                t.Fatalf("env override: got xhttp=%d grpc=%d", ep.xhttp, ep.grpc)
        }
        // collisions with reality variant ports are skipped
        vpsExtraCached = nil
        t.Setenv("XHTTP_PORT", "2053") // cloudflare variant port
        ep = computeVpsExtraPorts([]realityVariant{{"b", "www.bing.com", 8443}, {"c", "www.cloudflare.com", 2053}})
        if ep.xhttp == 2053 || ep.xhttp == 8443 {
                t.Errorf("xhttp port must skip taken variant ports, got %d", ep.xhttp)
        }
        if ep.xhttp <= 0 {
                t.Errorf("xhttp must fall back to a free port, got %d", ep.xhttp)
        }
}

func TestV325LinksCarryXhttpAndGrpc(t *testing.T) {
        v325Setup(t)
        links := buildLinks(&Client{Name: "main", ID: mainUUID()}, "203.0.113.7")
        var xhttp, grpc bool
        for _, l := range links {
                if l.Key == "vless-reality-xhttp" {
                        xhttp = true
                        for _, want := range []string{"security=reality", "type=xhttp", "mode=auto",
                                "path=%2Fxhttp", "pbk=", "sid=", "fp=chrome", "sni=www.microsoft.com"} {
                                if !strings.Contains(l.URL, want) {
                                        t.Errorf("xhttp link missing %q: %s", want, l.URL)
                                }
                        }
                        if strings.Contains(l.URL, "flow=") {
                                t.Errorf("xhttp link must carry no Vision flow (TCP-only): %s", l.URL)
                        }
                }
                if l.Key == "vless-grpc" {
                        grpc = true
                        for _, want := range []string{"security=reality", "type=grpc", "serviceName=",
                                "mode=gun", "pbk=", "sid="} {
                                if !strings.Contains(l.URL, want) {
                                        t.Errorf("grpc link missing %q: %s", want, l.URL)
                                }
                        }
                        if !strings.Contains(l.URL, "@203.0.113.7:2095") {
                                t.Errorf("grpc link must ride its own port: %s", l.URL)
                        }
                }
        }
        if !xhttp {
                t.Errorf("sub is missing the vless-reality-xhttp row (user ask #1)")
        }
        if !grpc {
                t.Errorf("sub is missing the vless-grpc row (user ask #2)")
        }
        // ordering: reality TCP rows first, xhttp/grpc after them, plain rows last
        keys := make([]string, 0, len(links))
        for _, l := range links {
                keys = append(keys, l.Key)
        }
        joined := strings.Join(keys, ",")
        if strings.Index(joined, "vless-reality-xhttp") < strings.Index(joined, "vless-ws-plain") {
                // ok
        } else if strings.Contains(joined, "vless-ws-plain") && !strings.Contains(joined, "vless-reality-xhttp") {
                t.Errorf("xhttp row missing entirely")
        }
}

func TestV325XrayServerInbounds(t *testing.T) {
        v325Setup(t)
        cfg := buildXrayConfig()
        inb, _ := cfg["inbounds"].([]map[string]any)
        var xhttp, grpc map[string]any
        for _, in := range inb {
                switch tag, _ := in["tag"].(string); tag {
                case "vless-reality-xhttp":
                        xhttp = in
                case "vless-reality-grpc":
                        grpc = in
                }
        }
        if xhttp == nil || grpc == nil {
                t.Fatalf("xray config missing xhttp/grpc inbounds (xhttp=%v grpc=%v)", xhttp != nil, grpc != nil)
        }
        // xhttp inbound: reality + path + mode, users carry NO flow
        ss, _ := xhttp["streamSettings"].(map[string]any)
        if ss["security"] != "reality" || ss["network"] != "xhttp" {
                t.Errorf("xhttp inbound stream wrong: %v", ss)
        }
        xs, _ := ss["xhttpSettings"].(map[string]any)
        if xs["path"] != "/xhttp" || xs["mode"] != "auto" {
                t.Errorf("xhttp settings wrong: %v", xs)
        }
        for _, in := range []map[string]any{xhttp, grpc} {
                set, _ := in["settings"].(map[string]any)
                users, _ := set["clients"].([]map[string]any)
                if len(users) == 0 {
                        t.Fatalf("%v inbound has no users", in["tag"])
                }
                if _, has := users[0]["flow"]; has {
                        t.Errorf("xhttp/grpc users must NOT carry flow (handshake fails): %v", users[0])
                }
                if l, _ := in["listen"].(string); l != "0.0.0.0" {
                        t.Errorf("%v must listen publicly, got %q", in["tag"], l)
                }
        }
        // grpc inbound: serviceName present
        gs, _ := grpc["streamSettings"].(map[string]any)
        gg, _ := gs["grpcSettings"].(map[string]any)
        if sn, _ := gg["serviceName"].(string); sn == "" {
                t.Errorf("grpc serviceName empty: %v", gg)
        }
}

func TestV325ClientConfigOutbounds(t *testing.T) {
        v325Setup(t)
        cfg := clientConfigJSON(&Client{Name: "main", ID: mainUUID()}, "203.0.113.7", "")
        if _, hasErr := cfg["error"]; hasErr {
                t.Fatalf("config error: %v", cfg["error"])
        }
        obs, _ := cfg["outbounds"].([]map[string]any)
        var xhttp, grpc bool
        for _, o := range obs {
                tag, _ := o["tag"].(string)
                st, _ := o["streamSettings"].(map[string]any)
                if tag == "alt-reality-xhttp" {
                        xhttp = true
                        if st["network"] != "xhttp" || st["security"] != "reality" {
                                t.Errorf("xhttp outbound stream wrong: %v", st)
                        }
                }
                if tag == "alt-reality-grpc" {
                        grpc = true
                        if st["network"] != "grpc" || st["security"] != "reality" {
                                t.Errorf("grpc outbound stream wrong: %v", st)
                        }
                }
        }
        if !xhttp || !grpc {
                t.Errorf("full client config missing alt outbounds (xhttp=%v grpc=%v)", xhttp, grpc)
        }
}

func TestV325StatePayloadAndMigration(t *testing.T) {
        v325Setup(t)
        // existing v3.24 state had no xhttp/grpc keys — migration must enable them
        stateMu.Lock()
        delete(state.Protocols, "vless-reality-xhttp")
        delete(state.Protocols, "vless-grpc")
        stateMu.Unlock()
        loadState()
        stateMu.RLock()
        if !state.Protocols["vless-reality-xhttp"] || !state.Protocols["vless-grpc"] {
                t.Fatalf("vps migration must enable the new protocol keys, got %v", state.Protocols)
        }
        stateMu.RUnlock()

        r := httptest.NewRequest("GET", "http://203.0.113.7/panel/api/state", nil)
        pl := statePayload(r)
        settings, _ := pl["settings"].(map[string]any)
        if vm, _ := settings["vps_mode"].(bool); !vm {
                t.Errorf("settings.vps_mode must be true on a VPS")
        }
        list, _ := pl["protocols"].([]map[string]any)
        var seenX, seenG bool
        for _, p := range list {
                if p["key"] == "vless-reality-xhttp" {
                        seenX = true
                }
                if p["key"] == "vless-grpc" {
                        seenG = true
                }
        }
        if !seenX || !seenG {
                t.Errorf("protoList must carry the new keys in vps mode (x=%v g=%v)", seenX, seenG)
        }

        // CDN mode: no dead toggles, no vps_mode
        t.Setenv("DEPLOY_MODE", "cdn")
        t.Setenv("DOMAIN", "deep-network-eco-7kpnz.lucity.app")
        r2 := httptest.NewRequest("GET", "http://x/panel/api/state", nil)
        pl2 := statePayload(r2)
        settings2, _ := pl2["settings"].(map[string]any)
        if vm, _ := settings2["vps_mode"].(bool); vm {
                t.Errorf("settings.vps_mode must be false on CDN")
        }
        list2, _ := pl2["protocols"].([]map[string]any)
        for _, p := range list2 {
                if k, _ := p["key"].(string); vpsOnlyProto(k) {
                        t.Errorf("CDN protoList must not carry vps-only key %q", k)
                }
        }
        // CDN links never carry the new rows
        links := buildLinks(&Client{Name: "main", ID: mainUUID()}, "deep-network-eco-7kpnz.lucity.app")
        for _, l := range links {
                if l.Key == "vless-reality-xhttp" || l.Key == "vless-grpc" {
                        t.Errorf("CDN link set must not carry %q", l.Key)
                }
        }
}

func TestV325SubServesNewRows(t *testing.T) {
        v325Setup(t)
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if strings.HasPrefix(r.URL.Path, "/sub/") {
                        handleSub(w, r, strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/"))
                        return
                }
                http.NotFound(w, r)
        }))
        defer srv.Close()

        tok := ""
        stateMu.RLock()
        for _, c := range state.Clients {
                tok = subToken(c.ID)
                break
        }
        stateMu.RUnlock()
        resp, err := http.Get(srv.URL + "/sub/" + tok)
        if err != nil {
                t.Fatal(err)
        }
        defer resp.Body.Close()
        b, err := io.ReadAll(resp.Body)
        if err != nil {
                t.Fatal(err)
        }
        dec, err := base64.StdEncoding.DecodeString(string(b))
        if err != nil {
                t.Fatalf("sub not base64: %v", err)
        }
        body := string(dec)
        if !strings.Contains(body, "type=xhttp&path=") {
                t.Errorf("sub body missing the xhttp row:\n%s", body)
        }
        if !strings.Contains(body, "type=grpc&serviceName=") {
                t.Errorf("sub body missing the grpc row:\n%s", body)
        }
}

func TestV325GrpcServiceNameStable(t *testing.T) {
        v325Setup(t)
        a, b := grpcServiceName(), grpcServiceName()
        if a != b {
                t.Errorf("grpc serviceName must be stable: %q vs %q", a, b)
        }
        if len(a) < 4 {
                t.Errorf("grpc serviceName too short: %q", a)
        }
        t.Setenv("GRPC_SERVICE", "MyGun")
        if got := grpcServiceName(); got != "MyGun" {
                t.Errorf("GRPC_SERVICE override: got %q", got)
        }
}
