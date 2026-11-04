package main

// ─────────── v3.24: VPS direct mode — "the sub links don't work" fix ───────────
// The panel was born on a CDN-fronted PaaS (Lucity): every ws-family link
// assumed TLS@443 terminates at the CDN edge and the panel URL was always
// https://<domain>. On a bare VPS none of that exists:
//   * port 443 is the REALITY inbound — a TLS-ws link pointed there is a
//     guaranteed handshake failure → every CDN-style row showed -1;
//   * the panel rides plain HTTP on PORT (80) — an https:// sub URL into a
//     plaintext port is exactly "لینک ساب کار نمی‌کند" in v2rayNG;
//   * the Reality link was emitted LAST (v2rayNG tests rows top-down), so
//     even a healthy install looked dead until the last row.
// This module detects the deployment shape and re-shapes links, sub URLs
// and the boot banner accordingly. CDN mode is untouched.

import (
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"
)

// vpsMode: true when the panel serves clients directly off its own IP
// (self-hosted VPS / local dev) — no TLS-terminating CDN in front.
// Signals: DEPLOY_MODE env (set by install.sh), else DOMAIN unset or an
// IP literal. Lucity deploys carry DOMAIN=*.lucity.app → false.
func vpsMode() bool {
        if v := strings.TrimSpace(os.Getenv("DEPLOY_MODE")); v != "" {
                return strings.EqualFold(v, "vps")
        }
        dom := strings.TrimSpace(os.Getenv("DOMAIN"))
        return dom == "" || isIPLiteral(dom)
}

// panelPublicPort is the port clients dial to reach the panel HTTP surface
// (also the port plain-ws fallback links ride on a VPS).
func panelPublicPort() int { return envInt("PORT", 8080) }

// ── public-address self-heal (old installs never had TCP_HOST) ──

var (
        pubIPMu    sync.Mutex
        pubIPCache string
        pubIPAt    time.Time
)

// detectPublicIP asks an IP echo service once (10-min cache). Only used in
// VPS mode when neither TCP_HOST nor DOMAIN carries an IP — heals installs
// made before install.sh started writing TCP_HOST.
func detectPublicIP() string {
        pubIPMu.Lock()
        if pubIPCache != "" && time.Since(pubIPAt) < 10*time.Minute {
                c := pubIPCache
                pubIPMu.Unlock()
                return c
        }
        pubIPMu.Unlock()
        for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip"} {
                client := http.Client{Timeout: 6 * time.Second}
                resp, err := client.Get(u)
                if err != nil {
                        continue
                }
                b := make([]byte, 64)
                n, _ := resp.Body.Read(b)
                resp.Body.Close()
                ip := strings.TrimSpace(string(b[:n]))
                if v4 := net.ParseIP(ip); v4 != nil && v4.To4() != nil && !v4.IsLoopback() && !v4.IsPrivate() {
                        pubIPMu.Lock()
                        pubIPCache = ip
                        pubIPAt = time.Now()
                        pubIPMu.Unlock()
                        return ip
                }
        }
        return ""
}

// vpsRealityAddr resolves the address Reality links ride on a VPS:
// TCP_HOST → DOMAIN (when an IP) → auto-detected public IP.
func vpsRealityAddr() string {
        if s := strings.TrimSpace(os.Getenv("TCP_HOST")); isIPLiteral(s) || hostRe.MatchString(s) {
                return strings.Trim(s, "[]")
        }
        if dom := strings.TrimSpace(os.Getenv("DOMAIN")); isIPLiteral(dom) {
                return strings.Trim(dom, "[]")
        }
        return detectPublicIP()
}

// vpsRealityPort: TCP_PORT → TCP_APP_PORT → 443 (the one port every
// operator lets through).
func vpsRealityPort() int {
        if p := atoi(strings.TrimSpace(os.Getenv("TCP_PORT")), 0); p > 0 {
                return p
        }
        if p := tcpAppPort(); p > 0 && p != 9000 {
                return p
        }
        return 443
}

// vpsTCPReady — like tcpReady() but with the VPS fallbacks baked in.
func vpsTCPReady() bool { return vpsRealityAddr() != "" && realityPub != "" }

// portAvailable probes whether a TCP port is free to listen on — used to
// decide whether the extra Reality-SNI inbounds can ride (a bind failure
// inside xray would kill EVERY tunnel, so extras are skipped when taken).
func portAvailable(port int) bool {
        ln, err := net.Listen("tcp", ":"+itoa(port))
        if err != nil {
                return false
        }
        _ = ln.Close()
        return true
}

// realityVariant — one Reality inbound: SNI on the wire + the port it rides.
type realityVariant struct {
        label string
        sni   string
        port  int
}

// realityTagFor builds a unique xray inbound tag per port (stats routing).
func realityTagFor(port int) string {
        if port == tcpAppPort() {
                return "vless-reality"
        }
        return "vless-reality-" + itoa(port)
}

// realityVariantsCached — computed ONCE at boot (before xray spawns and
// binds the ports) and reused for the xray config and every sub request:
// probing later would see our own listener and drop the variants.
var realityVariantsCached []realityVariant

func computeRealityVariants(primaryPort int) []realityVariant {
        if realityVariantsCached != nil {
                return realityVariantsCached
        }
        realityVariantsCached = buildRealityVariants(primaryPort)
        return realityVariantsCached
}

// realityVariants is the VPS Reality trio: the primary SNI on the primary
// port, plus two alternates on extra ports — three different TLS
// fingerprints on the wire, so an ISP that chokes one SNI pattern leaves
// the other rows alive (microsoft / bing / cloudflare). A taken port or a
// duplicate SNI silently drops that variant (never risks the primary).
func realityVariants(primaryPort int) []realityVariant {
        if realityVariantsCached != nil {
                return realityVariantsCached
        }
        return buildRealityVariants(primaryPort)
}

func buildRealityVariants(primaryPort int) []realityVariant {
        stateMu.RLock()
        primary := state.RealitySNI
        stateMu.RUnlock()
        if primary == "" {
                primary = "www.microsoft.com"
        }
        out := []realityVariant{{label: "VLESS-Reality-TCP", sni: primary, port: primaryPort}}
        add := func(label, sni string, port int) {
                if sni == "" || sni == primary || port <= 0 || port == primaryPort {
                        return
                }
                if !portAvailable(port) {
                        logf("reality variant %s skipped - port %d busy", sni, port)
                        return
                }
                for _, v := range out {
                        if v.sni == sni || v.port == port {
                                return
                        }
                }
                out = append(out, realityVariant{label: label, sni: sni, port: port})
        }
        add("VLESS-Reality-Bing", envStr("REALITY_SNI2", "www.bing.com"), envInt("REALITY_PORT2", 8443))
        add("VLESS-Reality-Cloudflare", envStr("REALITY_SNI3", "www.cloudflare.com"), envInt("REALITY_PORT3", 2053))
        return out
}

// ─────────── v3.25: Reality XHTTP + gRPC — the user-asked transports ───────────
//
// Both verified against Xray 26.10.31 (scripts/xray_transport_matrix.sh):
// VLESS+Reality+XHTTP and VLESS+Reality+gRPC each carry a full tunnel
// (204 OK, 120+ Mbit/s). gRPC rides REALITY too — no self-signed cert, no
// allowInsecure (which Xray 26 clients removed outright). One caveat kept
// in mind: Xray marks gRPC "deprecated" (log warning) but fully functional.

type vpsExtraPorts struct {
        xhttp int // 0 = every candidate port was taken → row skipped
        grpc  int
}

var vpsExtraCached *vpsExtraPorts

// computeVpsExtraPorts picks the public ports for the Reality-XHTTP and
// Reality-gRPC inbounds — probed ONCE at boot (before xray binds anything,
// same contract as computeRealityVariants) and cached afterwards. Candidate
// order: env override → default → the remaining Cloudflare-friendly ports.
func computeVpsExtraPorts(variants []realityVariant) *vpsExtraPorts {
        if vpsExtraCached != nil {
                return vpsExtraCached
        }
        taken := map[int]bool{panelPublicPort(): true, apiPort: true, tcpAppPort(): true, 9000: true}
        for _, v := range variants {
                taken[v.port] = true
        }
        pick := func(def int, alts []int) int {
                for _, p := range append([]int{def}, alts...) {
                        if p <= 0 || p > 65535 || taken[p] {
                                continue
                        }
                        if !portAvailable(p) {
                                logf("v3.25 transport port %d busy - trying next", p)
                                continue
                        }
                        taken[p] = true
                        return p
                }
                return 0
        }
        xp := pick(envInt("XHTTP_PORT", 2087), []int{8880, 2052, 2082})
        gp := pick(envInt("GRPC_PORT", 2095), []int{2082, 2052, 8880})
        vpsExtraCached = &vpsExtraPorts{xhttp: xp, grpc: gp}
        return vpsExtraCached
}

// grpcServiceName: stable per-install service name (GRPC_SERVICE overrides).
func grpcServiceName() string {
        if s := strings.TrimSpace(os.Getenv("GRPC_SERVICE")); s != "" {
                return s
        }
        h := sha256.Sum256([]byte(secret() + ":grpc"))
        return fmt.Sprintf("dn%x", h[:5])
}

// subURLScheme: the scheme subscription/panel URLs must carry.
func subURLScheme() string {
        if vpsMode() {
                return "http"
        }
        return "https"
}

// subURLHostPort: host[:port] for panel/sub URLs. In VPS mode the public
// port must ride the URL (http://1.2.3.4:8080) — omit for :80.
func subURLHostPort(r *http.Request) string {
        host := requestHost(r)
        if vpsMode() {
                if dom := strings.TrimSpace(os.Getenv("DOMAIN")); dom != "" {
                        host = dom
                }
                if p := panelPublicPort(); p != 80 {
                        host = host + ":" + itoa(p)
                }
        }
        return host
}

// panelURL builds the panel address for banner/UI/API in one place.
func panelURL(r *http.Request) string {
        if r == nil {
                host := ""
                if vpsMode() {
                        host = vpsPanelHost()
                } else {
                        host = strings.TrimSpace(os.Getenv("DOMAIN"))
                }
                if host == "" {
                        host = "<your-domain>"
                }
                return subURLScheme() + "://" + host + "/panel"
        }
        return subURLScheme() + "://" + subURLHostPort(r) + "/panel"
}

// vpsPanelHost: the banner's panel host in VPS mode (IP:port, no request).
func vpsPanelHost() string {
        host := vpsRealityAddr()
        if host == "" {
                host = "<server-ip>"
        }
        if p := panelPublicPort(); p != 80 {
                return host + ":" + itoa(p)
        }
        return host
}

// ─────────── the VPS link set: Reality first, plain-ws fallbacks ───────────

// buildVpsLinks emits the self-hosted subscription rows:
//  1. VLESS-Reality-TCP (Vision) — THE row: bare IP, no domain, no CDN
//     detour → lowest ping, full line speed, works on Irancell / MCI /
//     Rightel / ADSL when the IP is clean;
//  2. plain (security=none) ws-family fallbacks on the panel port — the
//     life-saver when an ISP starts throttling/killing the Reality port:
//     no TLS → nothing to handshake-filter, still proxies fine.
//
// No TLS-ws rows: port 443 is Reality on a VPS — TLS there is a -1 row.
func buildVpsLinks(c *Client, host string) []Link {
        allowed := userProtocols(c)
        cid := c.ID
        addr := vpsRealityAddr()
        uriAddr := bracketV6(addr)
        t := tuningGet()
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        stateMu.RLock()
        fmtStr := state.CfgFmt
        if fmtStr == "" {
                fmtStr = defaultCfgFmt
        }
        stateMu.RUnlock()
        city, cc := geoCityFor(addr)
        geo := geoToken(city, cc, 0, "⚡", "DIRECT")
        nm := func(label, proto, net_, sec, server string) string {
                return fmtName(fmtStr, c, shortLabel(label), proto, net_, sec, server, geo)
        }
        var out []Link

        // 1) Reality TRIO — first rows, the ones v2rayNG auto-tests first:
        //    primary SNI on the primary port + bing/cloudflare alternates on
        //    extra ports (v3.24: operator SNI-diversity, see realityVariants).
        vars := []realityVariant(nil)
        if vpsTCPReady() && allowed["vless-reality"] {
                vars = realityVariants(vpsRealityPort())
                for _, rv := range vars {
                        n6 := nm(rv.label, "VLESS", "TCP", "Reality", orStr(addr, host))
                        key := "vless-reality"
                        if rv.port != vpsRealityPort() {
                                key = "vless-reality-" + itoa(rv.port)
                        }
                        out = append(out, Link{key, "VLESS · Reality · " + rv.sni,
                                fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&spx=%%2F&type=tcp&headerType=none#%s",
                                        cid, uriAddr, rv.port, pyQuote(rv.sni), pyQuote(fp), pyQuote(realityPub),
                                        pyQuote(realitySID), pyQuote(n6))})
                }
        }

        // 1b) v3.25: Reality XHTTP + gRPC — same keys, extra transports (the
        // user-asked rows). XHTTP looks like ordinary web upload traffic to
        // DPI; gRPC adds an h2-based path. Both dial the primary SNI.
        if vpsTCPReady() {
                stateMu.RLock()
                sni := state.RealitySNI
                stateMu.RUnlock()
                if sni == "" {
                        sni = "www.microsoft.com"
                }
                ep := computeVpsExtraPorts(vars)
                if ep.xhttp > 0 && allowed["vless-reality-xhttp"] {
                        nx := nm("VLESS-Reality-XHTTP", "VLESS", "XHTTP", "Reality", orStr(addr, host))
                        out = append(out, Link{"vless-reality-xhttp", "VLESS · Reality · XHTTP",
                                fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=xhttp&path=%s&host=%s&mode=auto#%s",
                                        cid, uriAddr, ep.xhttp, pyQuote(sni), pyQuote(fp), pyQuote(realityPub), pyQuote(realitySID),
                                        pyQuote(xhttpPath()), pyQuote(sni), pyQuote(nx))})
                }
                if ep.grpc > 0 && allowed["vless-grpc"] {
                        ng := nm("VLESS-Reality-gRPC", "VLESS", "gRPC", "Reality", orStr(addr, host))
                        out = append(out, Link{"vless-grpc", "VLESS · Reality · gRPC",
                                fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=grpc&serviceName=%s&mode=gun#%s",
                                        cid, uriAddr, ep.grpc, pyQuote(sni), pyQuote(fp), pyQuote(realityPub), pyQuote(realitySID),
                                        pyQuote(grpcServiceName()), pyQuote(ng))})
                }
        }

        // 2) plain-ws fallbacks on the panel port (no TLS on a bare VPS).
        pp := panelPublicPort()
        wsHost := host
        if wsHost == "" {
                wsHost = addr
        }
        if allowed["vless-ws"] {
                n1 := nm("VLESS-WS", "VLESS", "WS", "HTTP", orStr(addr, host))
                out = append(out, Link{"vless-ws-plain", "VLESS · WS · جایگزین",
                        fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=none&type=ws&host=%s&path=%s#%s",
                                cid, uriAddr, pp, pyQuote(wsHost), pyQuote(wsPath()+"?ed=2048"), pyQuote(n1))})
        }
        if allowed["vless-hu"] {
                n3 := nm("VLESS-HTTPUpgrade", "VLESS", "HTTPUpgrade", "HTTP", orStr(addr, host))
                out = append(out, Link{"vless-hu-plain", "VLESS · HTTPUpgrade · جایگزین",
                        fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=none&type=httpupgrade&host=%s&path=%s#%s",
                                cid, uriAddr, pp, pyQuote(wsHost), pyQuote(huPath()), pyQuote(n3))})
        }
        if allowed["vmess-ws"] {
                n4 := nm("VMess-WS", "VMess", "WS", "HTTP", orStr(addr, host))
                vm := map[string]any{"v": "2", "ps": n4, "add": addr, "port": itoa(pp), "id": cid, "aid": "0",
                        "scy": "auto", "net": "ws", "type": "none", "host": wsHost, "path": vmessPath() + "?ed=2048",
                        "tls": "", "sni": "", "alpn": "", "fp": ""}
                b, _ := json.Marshal(vm)
                out = append(out, Link{"vmess-ws-plain", "VMess · WS · جایگزین",
                        "vmess://" + base64.StdEncoding.EncodeToString(b)})
        }
        if allowed["trojan-ws"] {
                n5 := nm("Trojan-WS", "Trojan", "WS", "HTTP", orStr(addr, host))
                out = append(out, Link{"trojan-ws-plain", "Trojan · WS · جایگزین",
                        fmt.Sprintf("trojan://%s@%s:%d?security=none&type=ws&host=%s&path=%s#%s",
                                cid, uriAddr, pp, pyQuote(wsHost), pyQuote(trojanPath()+"?ed=2048"), pyQuote(n5))})
        }

        // custom inbounds ride too (admin-defined), as-is.
        stateMu.RLock()
        var customs []*Inbound
        for _, ib := range state.Inbounds {
                cp := *ib
                customs = append(customs, &cp)
        }
        stateMu.RUnlock()
        for _, ib := range customs {
                if ib.Security == "reality" && realityPub == "" {
                        continue
                }
                lbl := fmt.Sprintf("%s · %s · %s · %s", ib.Name, strings.ToUpper(ib.Protocol), ib.Network, ib.Security)
                out = append(out, Link{ib.Tag, lbl, customLink(ib, c, addr, fmtStr, host)})
        }
        return out
}

// ─────────── v3.24: the VPS full-client config (?fmt=xray) ───────────
//
// Same job as clientConfigJSON, shaped for a bare VPS: the Reality outbound
// leads, plain-ws fallbacks follow on the panel port, no CDN/origin rows.
// The operator profiles (irancell / mci / tci / …) still apply — their
// fragment values ride the sockopt of the ws fallbacks (fragment only
// matters where a TLS ClientHello exists; Reality handles its own hello).
func vpsClientConfigJSON(c *Client, host, profile string) map[string]any {
        t := tuningGet()
        switch {
        case profile == "fast":
                t = &Tuning{Enabled: t.Enabled, Profile: t.Profile, FP: t.FP, CipherSuites: t.CipherSuites,
                        ALPN: t.ALPN, FragOn: false, FragPackets: t.FragPackets, FragLengths: t.FragLengths,
                        FragDelays: t.FragDelays, FragMaxsplit: t.FragMaxsplit, NoiseOn: false, NoiseRand: t.NoiseRand, NoiseDelay: t.NoiseDelay}
        case profile != "" && profile != "auto" && profile != "custom":
                if p, ok := operatorProfiles[profile]; ok {
                        t = &Tuning{Enabled: t.Enabled, Profile: profile, FP: p.FP, CipherSuites: t.CipherSuites,
                                ALPN: t.ALPN, FragOn: true, FragPackets: t.FragPackets, FragLengths: p.FragLengths,
                                FragDelays: p.FragDelays, FragMaxsplit: t.FragMaxsplit, NoiseOn: false, NoiseRand: t.NoiseRand, NoiseDelay: t.NoiseDelay}
                }
        }
        allowed := userProtocols(c)
        cid := c.ID
        addr := vpsRealityAddr()
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        pp := panelPublicPort()
        wsHost := host
        if wsHost == "" {
                wsHost = addr
        }

        sockopt := map[string]any{"tcpNoDelay": true, "tcpFastOpen": true,
                "tcpKeepAliveIdle": 300, "tcpKeepAliveInterval": 15}

        var outbounds []map[string]any
        var order []string
        tagFor := func(alt string) string {
                if len(order) == 0 {
                        return "proxy"
                }
                return alt
        }

        // 1) Reality — the primary outbound, mux OFF (Vision + mux = speed killer).
        var sniPrimary string
        vars := []realityVariant(nil)
        if vpsTCPReady() && allowed["vless-reality"] {
                stateMu.RLock()
                sniPrimary = state.RealitySNI
                stateMu.RUnlock()
                if sniPrimary == "" {
                        sniPrimary = "www.microsoft.com"
                }
                vars = realityVariants(vpsRealityPort())
                outbounds = append(outbounds, map[string]any{
                        "tag": "proxy", "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": addr, "port": vpsRealityPort(),
                                "users": []map[string]any{{"id": cid, "encryption": "none", "flow": "xtls-rprx-vision", "level": 0}}}}},
                        "streamSettings": map[string]any{"network": "tcp", "security": "reality",
                                "realitySettings": map[string]any{"show": false, "fingerprint": fp, "serverName": sniPrimary,
                                        "publicKey": realityPub, "shortId": realitySID, "spiderX": "/"},
                                "sockopt": map[string]any{"tcpNoDelay": true, "tcpFastOpen": true, "tcpKeepAliveIdle": 300}},
                        "mux": map[string]any{"enabled": false, "concurrency": -1}})
                order = append(order, "proxy")
        }

        // 1b) v3.25: Reality XHTTP + gRPC alt outbounds — same keys, extra
        // transports; no Vision flow (TCP-only), mux stays off for speed.
        if vpsTCPReady() {
                ep := computeVpsExtraPorts(vars)
                realityStream := func(net_ string, extra map[string]any) map[string]any {
                        st := map[string]any{"network": net_, "security": "reality",
                                "realitySettings": map[string]any{"show": false, "fingerprint": fp, "serverName": sniPrimary,
                                        "publicKey": realityPub, "shortId": realitySID, "spiderX": "/"},
                                "sockopt": map[string]any{"tcpNoDelay": true, "tcpFastOpen": true, "tcpKeepAliveIdle": 300}}
                        for k, v := range extra {
                                st[k] = v
                        }
                        return st
                }
                if ep.xhttp > 0 && allowed["vless-reality-xhttp"] {
                        tag := tagFor("alt-reality-xhttp")
                        outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vless",
                                "settings": map[string]any{"vnext": []map[string]any{{
                                        "address": addr, "port": ep.xhttp,
                                        "users": []map[string]any{{"id": cid, "encryption": "none", "level": 0}}}}},
                                "streamSettings": realityStream("xhttp", map[string]any{
                                        "xhttpSettings": map[string]any{"path": xhttpPath(), "mode": "auto"}}),
                                "mux": map[string]any{"enabled": false, "concurrency": -1}})
                        order = append(order, tag)
                }
                if ep.grpc > 0 && allowed["vless-grpc"] {
                        tag := tagFor("alt-reality-grpc")
                        outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vless",
                                "settings": map[string]any{"vnext": []map[string]any{{
                                        "address": addr, "port": ep.grpc,
                                        "users": []map[string]any{{"id": cid, "encryption": "none", "level": 0}}}}},
                                "streamSettings": realityStream("grpc", map[string]any{
                                        "grpcSettings": map[string]any{"serviceName": grpcServiceName(), "multiMode": false}}),
                                "mux": map[string]any{"enabled": false, "concurrency": -1}})
                        order = append(order, tag)
                }
        }

        // 2) plain-ws fallbacks on the panel port (no TLS on a bare VPS).
        plainStream := func(net_, path string) map[string]any {
                st := map[string]any{"network": net_, "security": "none", "sockopt": sockopt}
                switch net_ {
                case "ws":
                        st["wsSettings"] = map[string]any{"path": path + "?ed=2048", "headers": map[string]any{"Host": wsHost}}
                default:
                        st["httpupgradeSettings"] = map[string]any{"path": path, "host": wsHost}
                }
                return st
        }
        if allowed["vless-ws"] {
                tag := tagFor("alt-vless-ws")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": addr, "port": pp,
                                "users": []map[string]any{{"id": cid, "encryption": "none", "flow": "", "level": 0}}}}},
                        "streamSettings": plainStream("ws", wsPath()), "mux": muxPayload(!t.MuxOff)})
                order = append(order, tag)
        }
        if allowed["vless-hu"] {
                tag := tagFor("alt-vless-hu")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": addr, "port": pp,
                                "users": []map[string]any{{"id": cid, "encryption": "none", "flow": "", "level": 0}}}}},
                        "streamSettings": plainStream("httpupgrade", huPath()), "mux": muxPayload(!t.MuxOff)})
                order = append(order, tag)
        }
        if allowed["vmess-ws"] {
                tag := tagFor("alt-vmess-ws")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vmess",
                        "settings": map[string]any{"vnext": []map[string]any{{"address": addr, "port": pp,
                                "users": []map[string]any{{"id": cid, "alterId": 0, "security": "auto", "level": 0}}}}},
                        "streamSettings": plainStream("ws", vmessPath()), "mux": muxPayload(!t.MuxOff)})
                order = append(order, tag)
        }
        if allowed["trojan-ws"] {
                tag := tagFor("alt-trojan-ws")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "trojan",
                        "settings":       map[string]any{"servers": []map[string]any{{"address": addr, "port": pp, "password": cid, "level": 0}}},
                        "streamSettings": plainStream("ws", trojanPath()), "mux": muxPayload(!t.MuxOff)})
                order = append(order, tag)
        }
        if len(outbounds) == 0 {
                return map[string]any{"error": "هیچ پروتکلی برای این کاربر فعال نیست"}
        }
        outbounds = append(outbounds,
                map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{
                        "domainStrategy": "UseIPv4", "sockopt": map[string]any{"tcpNoDelay": true, "tcpKeepAliveIdle": 300}}},
                map[string]any{"tag": "block", "protocol": "blackhole"})
        return map[string]any{
                "log": map[string]any{"loglevel": "warning"},
                "dns": map[string]any{"queryStrategy": "UseIPv4",
                        "servers": []string{"https://1.1.1.1/dns-query", "8.8.8.8", "localhost"}},
                "inbounds": []map[string]any{
                        {"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                                "settings": map[string]any{"auth": "noauth", "udp": true, "userLevel": 0},
                                "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false}},
                        {"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
                                "settings": map[string]any{"userLevel": 0},
                                "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": false}},
                },
                "outbounds": outbounds,
                "routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []map[string]any{
                        {"type": "field", "port": "443", "network": "udp", "outboundTag": "block"},
                        {"type": "field", "domain": []string{"geosite:category-ads-all"}, "outboundTag": "block"},
                        {"type": "field", "domain": []string{"geosite:category-ir", "regexp:.*\\.ir$"}, "outboundTag": "direct"},
                        {"type": "field", "ip": []string{"geoip:ir", "geoip:private"}, "outboundTag": "direct"},
                }},
        }
}
