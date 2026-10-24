package main

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net"
        "net/url"
        "regexp"
        "strconv"
        "strings"
        "time"
)

// ─────────── FinalMask / cipher suites / Iranian operator profiles (ported from v2.9) ───────────

var fpsList = []string{"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}
var alpnModes = []string{"", "http/1.1", "h2", "h2,http/1.1", "http/1.1,h2"}

var cipherPresets = map[string]string{
        "TLS13":        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "TLS13_FAST":   "TLS_AES_128_GCM_SHA256",
        "TLS12_AES":    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
        "TLS12_CHACHA": "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-CHACHA20-POLY1305",
}

type OpProfile struct {
        Label       string `json:"label"`
        Note        string `json:"note"`
        FragLengths string `json:"frag_lengths"`
        FragDelays  string `json:"frag_delays"`
        FP          string `json:"fp"`
}

// Operator presets: community starting points; every value is overridable in the panel.
var operatorProfiles = map[string]OpProfile{
        "auto":       {"خودکار (سریع‌ترین)", "بدون فرگمنت — کم‌ترین پینگ؛ SNI تصادفی خودش فیلتر SNI را دور می‌زند", "100-200", "10-20", "chrome"},
        "irancell":   {"ایرانسل", "فرگمنت سبک؛ فقط اگر با SNI تصادفی هم وصل نشد", "100-200", "10-20", "chrome"},
        "mci":        {"همراه اول", "سخت‌گیرترین DPI — فرگمنت کوچک‌تر برای عبور مطمئن", "40-100", "10-20", "chrome"},
        "rightel":    {"رایتل", "فرگمنت متوسط رایتل", "40-100", "10-20", "chrome"},
        "shatel":     {"شاتل", "خطوط ثابت معمولاً سبک‌تر فیلتر می‌شوند", "100-200", "5-15", "chrome"},
        "parsonline": {"پارس‌آنلاین", "فرگمنت سبک پارس‌آنلاین", "100-200", "10-20", "chrome"},
        "mobinnet":   {"مبین‌نت (TD-LTE)", "اثر انگشت فایرفاکس روی مبین‌نت بهتر جواب می‌دهد", "40-100", "10-20", "firefox"},
        "tci":        {"مخابرات (ADSL/VDSL)", "فرگمنت متوسط برای DPI خطوط ثابت", "40-100", "10-20", "chrome"},
        "asiatek":    {"آسیاتک", "فرگمنت سبک آسیاتک", "100-200", "10-20", "chrome"},
        "custom":     {"اختصاصی", "همه مقادیر را دستی تعیین کنید", "100-200", "10-20", "chrome"},
}

func defaultTuning() *Tuning {
        return &Tuning{Enabled: true, Profile: "auto", FP: "chrome", CipherSuites: "",
                ALPN: "", FragOn: false, FragPackets: "tlshello", FragLengths: "100-200",
                FragDelays: "10-20", FragMaxsplit: "3-6", NoiseOn: false, NoiseRand: "1-64", NoiseDelay: "10-20"}
}

// bracketV6 wraps a bare IPv6 literal in [] for URI-style links
// (vless://uuid@[2400:52e0::1]:443). IPv4 and hostnames pass through.
func bracketV6(addr string) string {
        a := strings.TrimSpace(addr)
        if strings.HasPrefix(a, "[") {
                return a
        }
        if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
                return "[" + a + "]"
        }
        return a
}

// muxPayload is the v3.7 speed-pack outbound mux block: enabled with
// concurrency 8 + xudp 8, or fully disabled (xhttp / Reality / mux_off).
func muxPayload(on bool) map[string]any {
        if !on {
                return map[string]any{"enabled": false, "concurrency": -1}
        }
        return map[string]any{"enabled": true, "concurrency": 8, "xudpConcurrency": 8}
}

var rangeCleanRe = regexp.MustCompile(`[^0-9\-,]`)

func cleanRange(v, fallback string) string {
        v = rangeCleanRe.ReplaceAllString(strings.ReplaceAll(v, " ", ""), "")
        if len(v) > 24 {
                v = v[:24]
        }
        if v == "" {
                return fallback
        }
        return v
}

func tuningSanitize(t *Tuning) *Tuning {
        base := defaultTuning()
        if t == nil {
                return base
        }
        prof := t.Profile
        if prof == "" {
                prof = "auto"
        }
        if p, ok := operatorProfiles[prof]; ok && prof != "custom" {
                base.Profile = prof
                base.FragLengths = p.FragLengths
                base.FragDelays = p.FragDelays
                base.FP = p.FP
        } else if _, ok := operatorProfiles[prof]; !ok {
                base.Profile = "custom"
        } else {
                base.Profile = prof
        }
        for _, f := range fpsList {
                if t.FP == f {
                        base.FP = t.FP
                }
        }
        var cs []string
        for _, x := range strings.Split(t.CipherSuites, ":") {
                if strings.TrimSpace(x) != "" {
                        cs = append(cs, strings.TrimSpace(x))
                }
        }
        base.CipherSuites = strings.Join(cs, ":")
        if len(base.CipherSuites) > 400 {
                base.CipherSuites = base.CipherSuites[:400]
        }
        alpn := strings.ReplaceAll(t.ALPN, " ", "")
        base.ALPN = alpn
        validAlpn := false
        for _, m := range alpnModes {
                if alpn == m {
                        validAlpn = true
                }
        }
        if !validAlpn {
                base.ALPN = ""
        }
        base.Enabled = t.Enabled
        base.FragOn = t.FragOn
        if t.FragPackets == "1-3" {
                base.FragPackets = "1-3"
        } else {
                base.FragPackets = "tlshello"
        }
        base.FragLengths = cleanRange(t.FragLengths, base.FragLengths)
        base.FragDelays = cleanRange(t.FragDelays, base.FragDelays)
        base.FragMaxsplit = cleanRange(t.FragMaxsplit, base.FragMaxsplit)
        base.NoiseOn = t.NoiseOn
        base.NoiseRand = cleanRange(t.NoiseRand, base.NoiseRand)
        base.NoiseDelay = cleanRange(t.NoiseDelay, base.NoiseDelay)
        // v3.7 speed pack: default (false) = Mux ON in exported JSON configs.
        base.MuxOff = t.MuxOff
        return base
}

func tuningGet() *Tuning {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return tuningSanitize(state.Tuning)
}

// finalMask emits the REAL xray sockopt.fragment / sockopt.noises payloads.
func finalMask(t *Tuning) map[string]any {
        if !t.Enabled || !t.FragOn {
                return nil
        }
        fm := map[string]any{"packets": t.FragPackets, "length": t.FragLengths, "interval": t.FragDelays}
        if t.NoiseOn {
                fm = map[string]any{
                        "packets": t.FragPackets, "length": t.FragLengths, "interval": t.FragDelays,
                        "noises": []map[string]any{{"type": "rand", "packetSize": t.NoiseRand, "delay": t.NoiseDelay}},
                }
        }
        return fm
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)

func isIPLiteral(s string) bool {
        s = strings.TrimSpace(s)
        if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
                s = s[1 : len(s)-1]
        }
        return net.ParseIP(s) != nil
}

func sniFor(addr, host string) string {
        stateMu.RLock()
        ov := strings.TrimSpace(state.SNIOverride)
        stateMu.RUnlock()
        if ov != "" {
                return ov
        }
        if isIPLiteral(addr) {
                if host != "" {
                        return host
                }
                return addr
        }
        return addr
}

// linkSNI rides a random subdomain of the platform wildcard zone: the DPI never
// sees a known hostname while the cert still validates and routing is unchanged.
// v3.15: when a PROVEN SNI front is active (bunny's shared *.b-cdn.net cert —
// the panel domain is DNS-poisoned inside Iran, the front removes it from the
// wire entirely) it takes precedence and applies to every emitted link.
func linkSNI(sniHost string) string {
        host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(sniHost)), ".")
        if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
                return sniHost
        }
        if s := frontFromState(); s != "" {
                return s
        }
        if !strings.HasSuffix(host, ".lucity.app") || host == "lucity.app" {
                return sniHost
        }
        stateMu.RLock()
        randomAllowed := state.RandomSNI
        stateMu.RUnlock()
        if !randomAllowed {
                return sniHost
        }
        return "ng" + randHex(5) + ".lucity.app"
}

func tcpReady() bool { return tcpHost() != "" && tcpPublicPort() != "" && realityPub != "" }

func tcpHost() string {
        if s := osGetenv("TCP_HOST"); s != "" {
                return s
        }
        return osGetenv("RAILWAY_TCP_PROXY_DOMAIN")
}

func tcpPublicPort() string {
        if s := osGetenv("TCP_PORT"); s != "" {
                return s
        }
        return osGetenv("RAILWAY_TCP_PROXY_PORT")
}

// fmtName renders the admin's config-name template with a safe fallback.
func fmtName(fmtStr string, c *Client, label, proto, net_, sec, server string) string {
        name := c.Name
        fallback := name + "-" + label
        if fmtStr == "" {
                fmtStr = "{name}-{label}"
        }
        if strings.ContainsAny(fmtStr, "{}") == false {
                return fmtStr
        }
        known := map[string]string{
                "name": name, "label": label, "proto": proto, "net": net_, "sec": sec,
                "server": server, "uuid8": firstN(c.ID, 8),
                "date": time.Now().UTC().Format("20060102"),
        }
        var b strings.Builder
        rest := fmtStr
        for {
                i := strings.IndexByte(rest, '{')
                if i < 0 {
                        b.WriteString(rest)
                        break
                }
                j := strings.IndexByte(rest[i:], '}')
                if j < 0 {
                        b.WriteString(rest)
                        break
                }
                j += i
                b.WriteString(rest[:i])
                key := rest[i+1 : j]
                v, ok := known[key]
                if !ok {
                        return fallback
                }
                b.WriteString(v)
                rest = rest[j+1:]
        }
        out := strings.Join(strings.Fields(b.String()), " ")
        out = strings.Trim(out, "-_ ")
        if out == "" {
                return fallback
        }
        return out
}

func firstN(s string, n int) string {
        if len(s) <= n {
                return s
        }
        return s[:n]
}

type Link struct {
        Key   string `json:"key"`
        Label string `json:"label"`
        URL   string `json:"url"`
}

func defaultALPN(net string) string {
        switch net {
        case "xhttp":
                return "h2,http/1.1"
        case "grpc":
                return "h2"
        default:
                return "http/1.1"
        }
}

func customLink(ib *Inbound, c *Client, addr, fmtStr, host string) string {
        cid, proto, net_, sec := c.ID, ib.Protocol, ib.Network, ib.Security
        nm := fmtName(fmtStr, c, ib.Name, strings.ToUpper(proto), strings.ToUpper(net_), strings.ToUpper(sec), addr)
        frag := pyQuote(nm)
        path := ib.Path
        t := tuningGet()
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        uriAddr := bracketV6(addr)
        alpnOv := strings.TrimSpace(t.ALPN)
        sniHost := sniFor(addr, host)
        if sec == "reality" {
                p := map[string]string{"encryption": "none", "security": "reality", "sni": ib.SNI,
                        "fp": fp, "pbk": realityPub, "sid": realitySID, "type": net_}
                if net_ == "tcp" {
                        p["flow"] = "xtls-rprx-vision"
                        p["headerType"] = "none"
                } else if net_ == "xhttp" {
                        p["path"] = path
                        p["mode"] = "auto"
                } else {
                        p["serviceName"] = strings.TrimPrefix(path, "/")
                        p["mode"] = "gun"
                }
                return "vless://" + cid + "@" + uriAddr + ":" + itoa(ib.Port) + "?" + encParams(p) + "#" + frag
        }
        alpn := alpnOv
        if alpn == "" {
                alpn = defaultALPN(net_)
        }
        tlsName := linkSNI(sniHost)
        if proto == "vmess" {
                v := map[string]any{"v": "2", "ps": nm, "add": addr, "port": "443", "id": cid, "aid": "0",
                        "scy": "auto", "net": net_, "type": map[bool]string{true: "gun", false: "none"}[net_ == "grpc"],
                        "host": sniHost, "path": map[bool]string{true: strings.TrimPrefix(path, "/"), false: path}[net_ == "grpc"],
                        "tls": "tls", "sni": tlsName, "alpn": alpn, "fp": fp}
                b, _ := json.Marshal(v)
                return "vmess://" + base64.StdEncoding.EncodeToString(b)
        }
        p := map[string]string{}
        if proto == "vless" {
                p["encryption"] = "none"
        }
        p["security"] = "tls"
        p["sni"] = tlsName
        p["fp"] = fp
        p["alpn"] = alpn
        p["type"] = net_
        p["host"] = sniHost
        if net_ == "grpc" {
                p["serviceName"] = strings.TrimPrefix(path, "/")
                p["mode"] = "gun"
        } else {
                p["path"] = path
        }
        if net_ == "xhttp" {
                p["mode"] = "packet-up"
        }
        return proto + "://" + cid + "@" + uriAddr + ":443?" + encParams(p) + "#" + frag
}

func encParams(p map[string]string) string {
        keys := make([]string, 0, len(p))
        for k := range p {
                keys = append(keys, k)
        }
        sortStrings(keys)
        var parts []string
        for _, k := range keys {
                parts = append(parts, pyQuote(k)+"="+pyQuote(p[k]))
        }
        return strings.Join(parts, "&")
}

// buildLinks generates every share link for one client (byte-compatible with
// the Python panel). v3.9: when the all-operator edge set (state.TopEdges) is
// active, the list expands to one variant per graded edge plus the DNS-auto
// entry — every client app then picks its best route per operator.
// v3.11: the national-internet kit (relay/direct/white-SNI survival variants)
// is appended last so daily traffic keeps the fast CDN paths.
func buildLinks(c *Client, host string) []Link {
        stateMu.RLock()
        addr := state.Address
        multi := state.MultiEdge && len(state.TopEdges) > 0
        edges := append([]*EdgeScore(nil), state.TopEdges...)
        stateMu.RUnlock()
        if addr == "" {
                addr = host
        }
        if !multi || host == "" {
                out := buildLinksAddr(c, addr, host, "", true)
                return appendLocalLinks(c, host, out)
        }
        out := buildLinksAddr(c, addr, host, "", true)
        seen := map[string]bool{}
        for _, l := range out {
                seen[l.URL] = true
        }
        // 🥇 is implicit for the primary (first) entries; variants get 🥈🥉…
        medals := []string{"\U0001F948", "\U0001F949", "E4", "E5"} // 🥈🥉
        rank := 0
        for _, e := range edges {
                if rank >= len(medals) {
                        break
                }
                if e.IP == addr {
                        continue // already the primary entry
                }
                city := e.City
                if city == "" {
                        city = e.CC
                }
                suf := fmt.Sprintf(" %s %s %dms", medals[rank], city, int(e.Med))
                for _, l := range buildLinksAddr(c, e.IP, host, suf, false) {
                        if !seen[l.URL] {
                                seen[l.URL] = true
                                out = append(out, l)
                        }
                }
                rank++
        }
        // DNS-auto: let bunny geo-DNS pick the per-operator PoP itself.
        if !isIPLiteral(host) && host != addr {
                for _, l := range buildLinksAddr(c, host, host, " \U0001F310 DNS", false) {
                        if !seen[l.URL] {
                                seen[l.URL] = true
                                out = append(out, l)
                        }
                }
        }
        return appendLocalLinks(c, host, out)
}

// appendLocalLinks adds the v3.11 local-mode survival variants (dedup'd) to a
// built link list — shared by both the single-address and multi-edge paths.
func appendLocalLinks(c *Client, host string, out []Link) []Link {
        seen := map[string]bool{}
        for _, l := range out {
                seen[l.URL] = true
        }
        for _, l := range buildLocalLinks(c, host) {
                if !seen[l.URL] {
                        seen[l.URL] = true
                        out = append(out, l)
                }
        }
        return out
}

// buildLinksAddr builds the full link set for one explicit address. Variants
// (primary=false) skip the Reality entry and custom inbounds — those do not
// vary with the CDN edge address, so repeating them would only add noise.
func buildLinksAddr(c *Client, addr, host, suffix string, primary bool) []Link {
        stateMu.RLock()
        sni := state.RealitySNI
        fmtStr := state.CfgFmt
        if fmtStr == "" {
                fmtStr = "{name}-{label}"
        }
        stateMu.RUnlock()
        nm := func(label, proto, net_, sec, server string) string {
                return fmtName(fmtStr, c, label, proto, net_, sec, server) + suffix
        }
        t := tuningGet()
        sniHost := sniFor(addr, host)
        tlsName := linkSNI(sniHost)
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        alpnOv := strings.TrimSpace(t.ALPN)
        cid := c.ID
        uriAddr := bracketV6(addr)
        allowed := userProtocols(c)
        var links []Link

        tlsParam := "security=tls&sni=" + pyQuote(tlsName) + "&fp=" + pyQuote(fp)
        addLink := func(key, label, url string) {
                links = append(links, Link{key, label, url})
        }
        if allowed["vless-ws"] {
                n1 := nm("VLESS-WS", "VLESS", "WS", "TLS", addr)
                addLink("vless-ws", "VLESS · WebSocket",
                        fmt.Sprintf("vless://%s@%s:443?encryption=none&%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                cid, uriAddr, tlsParam, pyQuote(orStr(alpnOv, "http/1.1")), pyQuote(sniHost),
                                pyQuote(wsPath()+"?ed=2048"), pyQuote(n1)))
        }
        if allowed["vless-xhttp"] {
                n2 := nm("VLESS-XHTTP", "VLESS", "XHTTP", "TLS", addr)
                addLink("vless-xhttp", "VLESS · XHTTP",
                        fmt.Sprintf("vless://%s@%s:443?encryption=none&%s&alpn=%s&type=xhttp&host=%s&path=%s&mode=packet-up#%s",
                                cid, uriAddr, tlsParam, pyQuote(orStr(alpnOv, "h2,http/1.1")), pyQuote(sniHost),
                                pyQuote(xhttpPath()), pyQuote(n2)))
        }
        if allowed["vless-hu"] {
                n3 := nm("VLESS-HTTPUpgrade", "VLESS", "HTTPUpgrade", "TLS", addr)
                addLink("vless-hu", "VLESS · HTTPUpgrade",
                        fmt.Sprintf("vless://%s@%s:443?encryption=none&%s&alpn=%s&type=httpupgrade&host=%s&path=%s#%s",
                                cid, uriAddr, tlsParam, pyQuote(orStr(alpnOv, "http/1.1")), pyQuote(sniHost),
                                pyQuote(huPath()), pyQuote(n3)))
        }
        if allowed["vmess-ws"] {
                n4 := nm("VMess-WS", "VMess", "WS", "TLS", addr)
                vm := map[string]any{"v": "2", "ps": n4, "add": addr, "port": "443", "id": cid, "aid": "0",
                        "scy": "auto", "net": "ws", "type": "none", "host": sniHost, "path": vmessPath() + "?ed=2048",
                        "tls": "tls", "sni": tlsName, "alpn": orStr(alpnOv, "http/1.1"), "fp": fp}
                b, _ := json.Marshal(vm)
                addLink("vmess-ws", "VMess · WebSocket", "vmess://"+base64.StdEncoding.EncodeToString(b))
        }
        if allowed["trojan-ws"] {
                n5 := nm("Trojan-WS", "Trojan", "WS", "TLS", addr)
                addLink("trojan-ws", "Trojan · WebSocket",
                        fmt.Sprintf("trojan://%s@%s:443?security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                cid, uriAddr, pyQuote(tlsName), pyQuote(fp), pyQuote(orStr(alpnOv, "http/1.1")),
                                pyQuote(sniHost), pyQuote(trojanPath()+"?ed=2048"), pyQuote(n5)))
        }
        if primary && tcpReady() && allowed["vless-reality"] {
                n6 := nm("VLESS-Reality-TCP", "VLESS", "TCP", "Reality", orStr(tcpHost(), addr))
                addLink("vless-reality", "VLESS · Reality (TCP Proxy)",
                        fmt.Sprintf("vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&spx=%%2F&type=tcp&headerType=none#%s",
                                cid, tcpHost(), tcpPublicPort(), pyQuote(sni), pyQuote(fp), pyQuote(realityPub),
                                pyQuote(realitySID), pyQuote(n6)))
        }
        stateMu.RLock()
        var customs []*Inbound
        for _, ib := range state.Inbounds {
                cp := *ib
                customs = append(customs, &cp)
        }
        stateMu.RUnlock()
        if !primary {
                customs = nil // edge variants: customs don't vary by CDN address
        }
        for _, ib := range customs {
                if ib.Security == "reality" && realityPub == "" {
                        continue
                }
                lbl := fmt.Sprintf("%s · %s · %s · %s", ib.Name, strings.ToUpper(ib.Protocol), ib.Network, ib.Security)
                addLink(ib.Tag, lbl, customLink(ib, c, addr, fmtStr, host))
        }
        return links
}

func orStr(a, b string) string {
        if a != "" {
                return a
        }
        return b
}

// linkDisplayName returns the client-facing config name: the URI fragment
// (vless/trojan) or the vmess "ps" field — both carry the full variant suffix
// (e.g. "main-VLESS-WS 🥈 Amsterdam 62ms"). Falls back to the label.
func linkDisplayName(l Link) string {
        if i := strings.LastIndex(l.URL, "#"); i >= 0 && i+1 < len(l.URL) {
                if frag, err := url.PathUnescape(l.URL[i+1:]); err == nil && strings.TrimSpace(frag) != "" {
                        return frag
                }
        }
        if strings.HasPrefix(l.URL, "vmess://") {
                var v struct {
                        Ps string `json:"ps"`
                }
                if b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(l.URL, "vmess://")); err == nil {
                        if json.Unmarshal(b, &v) == nil && v.Ps != "" {
                                return v.Ps
                        }
                }
        }
        return l.Label
}

// clientConfigJSON emits a full ready-to-import Xray client config for one user.
func clientConfigJSON(c *Client, host, profile string) map[string]any {
        stateMu.RLock()
        addr := state.Address
        if addr == "" {
                addr = host
        }
        sni := state.RealitySNI
        stateMu.RUnlock()
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
        sniHost := sniFor(addr, host)
        tlsName := linkSNI(sniHost)
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        cs := strings.TrimSpace(t.CipherSuites)
        alpnOv := strings.TrimSpace(t.ALPN)
        fm := finalMask(t)
        allowed := userProtocols(c)
        cid := c.ID

        tlsStream := func(net_, path string, alpn []string) map[string]any {
                if alpnOv != "" {
                        alpn = strings.Split(alpnOv, ",")
                }
                tls := map[string]any{"serverName": tlsName, "fingerprint": fp, "alpn": alpn, "allowInsecure": false}
                if cs != "" {
                        tls["cipherSuites"] = cs
                }
                sockopt := map[string]any{"tcpNoDelay": true, "tcpFastOpen": true,
                        "tcpKeepAliveIdle": 300, "tcpKeepAliveInterval": 15}
                for k, v := range fm {
                        sockopt[k] = v
                }
                stream := map[string]any{"network": net_, "security": "tls", "tlsSettings": tls, "sockopt": sockopt}
                switch net_ {
                case "ws":
                        stream["wsSettings"] = map[string]any{"path": path + "?ed=2048", "headers": map[string]any{"Host": sniHost}}
                case "httpupgrade":
                        stream["httpupgradeSettings"] = map[string]any{"path": path, "host": sniHost}
                default:
                        stream["xhttpSettings"] = map[string]any{"path": path, "mode": "packet-up", "host": sniHost}
                }
                return stream
        }

        vlessOut := func(tag string, port int, stream map[string]any, muxOn bool) map[string]any {
                return map[string]any{"tag": tag, "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": addr, "port": port,
                                "users": []map[string]any{{"id": cid, "encryption": "none", "flow": "", "level": 0}}}}},
                        "streamSettings": stream, "mux": muxPayload(muxOn)}
        }

        var outbounds []map[string]any
        var order []string
        tagFor := func(alt string) string {
                if len(order) == 0 {
                        return "proxy"
                }
                return alt
        }
        if tcpReady() && allowed["vless-reality"] {
                outbounds = append(outbounds, map[string]any{
                        "tag": "proxy", "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": tcpHost(), "port": atoi(tcpPublicPort(), 443),
                                "users": []map[string]any{{"id": cid, "encryption": "none", "flow": "xtls-rprx-vision", "level": 0}}}}},
                        "streamSettings": map[string]any{"network": "tcp", "security": "reality",
                                "realitySettings": map[string]any{"show": false, "fingerprint": fp, "serverName": sni,
                                        "publicKey": realityPub, "shortId": realitySID, "spiderX": "/"},
                                "sockopt": map[string]any{"tcpNoDelay": true, "tcpFastOpen": true, "tcpKeepAliveIdle": 300}},
                        "mux": map[string]any{"enabled": false, "concurrency": -1}})
                order = append(order, "proxy")
        }
        if allowed["vless-ws"] {
                tag := tagFor("alt-vless-ws")
                outbounds = append(outbounds, vlessOut(tag, 443, tlsStream("ws", wsPath(), []string{"http/1.1"}), !t.MuxOff))
                order = append(order, tag)
        }
        if allowed["vless-hu"] {
                tag := tagFor("alt-vless-hu")
                outbounds = append(outbounds, vlessOut(tag, 443, tlsStream("httpupgrade", huPath(), []string{"http/1.1"}), !t.MuxOff))
                order = append(order, tag)
        }
        if allowed["vless-xhttp"] {
                tag := tagFor("alt-vless-xhttp")
                outbounds = append(outbounds, vlessOut(tag, 443, tlsStream("xhttp", xhttpPath(), []string{"h2", "http/1.1"}), false))
                order = append(order, tag)
        }
        if allowed["vmess-ws"] {
                tag := tagFor("alt-vmess-ws")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "vmess",
                        "settings": map[string]any{"vnext": []map[string]any{{"address": addr, "port": 443,
                                "users": []map[string]any{{"id": cid, "alterId": 0, "security": "auto", "level": 0}}}}},
                        "streamSettings": tlsStream("ws", vmessPath(), []string{"http/1.1"}),
                        "mux":            muxPayload(!t.MuxOff)})
                order = append(order, tag)
        }
        if allowed["trojan-ws"] {
                tag := tagFor("alt-trojan-ws")
                outbounds = append(outbounds, map[string]any{"tag": tag, "protocol": "trojan",
                        "settings":       map[string]any{"servers": []map[string]any{{"address": addr, "port": 443, "password": cid, "level": 0}}},
                        "streamSettings": tlsStream("ws", trojanPath(), []string{"http/1.1"}),
                        "mux":            muxPayload(!t.MuxOff)})
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

func atoi(s string, def int) int {
        if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
                return n
        }
        return def
}

func itoa(n int) string { return strconv.Itoa(n) }
