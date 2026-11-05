package main

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net"
        "net/http"
        "net/url"
        "strings"
)

// ─────────── vless link building: Vision / XHTTP / gRPC (all Reality) ───────────

type Link struct {
        Key  string `json:"key"`
        Name string `json:"name"`
        URL  string `json:"url"`
        Net  string `json:"net"`
        Port int    `json:"port"`
}

// configName: the ⟦ NAME • PROTO ⟧ display name riding every link.
func configName(c *Client, proto, geo string) string {
        base := strings.TrimSpace(c.Name)
        if base == "" {
                base = "user"
        }
        return fmt.Sprintf("⟦ %s • %s • %s ⟧", mathBold(base), proto, geo)
}

func mathBold(s string) string {
        var b strings.Builder
        for _, r := range s {
                if r >= 'A' && r <= 'Z' {
                        b.WriteRune(r - 'A' + 0x1D5D4)
                } else if r >= 'a' && r <= 'z' {
                        b.WriteRune(r - 'a' + 0x1D5EE)
                } else if r >= '0' && r <= '9' {
                        b.WriteRune(r - '0' + 0x1D7EC)
                } else {
                        b.WriteRune(r)
                }
        }
        return b.String()
}

// linkAddr strips a trailing :port from the host (the proxy address is the
// bare IP/domain — the panel's HTTP port never rides the vless links).
func linkAddr(host string) string {
        h, p, err := net.SplitHostPort(host)
        if err != nil || p == "" {
                return host
        }
        if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
                return "[" + h + "]"
        }
        return h
}

// buildLinks: the full per-client config set — Vision (fastest, first),
// XHTTP (packet-up) and gRPC (h2), all Reality on the VPS address.
func buildLinks(c *Client, host string) []Link {
        if host == "" {
                host = publicHost()
        }
        host = linkAddr(host)
        ports := effectivePorts()
        snis := effectiveSNIs()
        geo := geoLabel()
        addr := host
        if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
                addr = "[" + addr + "]" // IPv6 literal
        }
        q := func(s string) string { return url.QueryEscape(s) }

        out := []Link{
                {
                        Key:  "vision",
                        Net:  "Vision",
                        Port: ports.Vision,
                        Name: configName(c, "VLESS·VISION", geo),
                        URL: fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s",
                                c.ID, addr, ports.Vision, q(snis.Vision), q(realityPub), q(realitySID), q(configName(c, "Vision", geo))),
                },
                {
                        Key:  "xhttp",
                        Net:  "XHTTP",
                        Port: ports.XHTTP,
                        Name: configName(c, "VLESS·XHTTP", geo),
                        URL: fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=xhttp&path=%s&host=%s#%s",
                                c.ID, addr, ports.XHTTP, q(snis.XHTTP), q(realityPub), q(realitySID), q(xhttpPath()), q(snis.XHTTP), q(configName(c, "XHTTP", geo))),
                },
                {
                        Key:  "grpc",
                        Net:  "gRPC",
                        Port: ports.GRPC,
                        Name: configName(c, "VLESS·GRPC", geo),
                        URL: fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=grpc&serviceName=%s&mode=gun#%s",
                                c.ID, addr, ports.GRPC, q(snis.GRPC), q(realityPub), q(realitySID), q(grpcService()), q(configName(c, "gRPC", geo))),
                },
        }
        return out
}

func linkDisplayName(l Link) string {
        if l.Name != "" {
                return l.Name
        }
        return l.Key
}

// clientConfigJSON: a ready-to-import Xray client config (?fmt=xray) —
// includes all three outbounds + auto-select routing, mux OFF (max speed).
func clientConfigJSON(c *Client, host string) map[string]any {
        if host == "" {
                host = publicHost()
        }
        host = linkAddr(host)
        ports := effectivePorts()
        snis := effectiveSNIs()
        addr := host
        if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
                addr = "[" + addr + "]"
        }

        realityClient := func(sni string) map[string]any {
                return map[string]any{
                        "serverName": sni, "fingerprint": "chrome",
                        "publicKey": realityPub, "shortId": realitySID, "spiderX": "/",
                }
        }
        outbound := func(tag, net string, port int, sni string, extra map[string]any) map[string]any {
                ss := map[string]any{"network": net, "security": "reality", "realitySettings": realityClient(sni)}
                for k, v := range extra {
                        ss[k] = v
                }
                return map[string]any{
                        "tag": tag, "protocol": "vless",
                        "settings": map[string]any{"vnext": []map[string]any{{
                                "address": addr, "port": port,
                                "users": []map[string]any{{"id": c.ID, "encryption": "none", "flow": flowFor(net)}},
                        }}},
                        "streamSettings": ss,
                        "mux":            map[string]any{"enabled": false, "concurrency": -1},
                }
        }

        links := []map[string]any{
                outbound("vision", "tcp", ports.Vision, snis.Vision, nil),
                outbound("xhttp", "xhttp", ports.XHTTP, snis.XHTTP, map[string]any{
                        "xhttpSettings": map[string]any{"path": xhttpPath(), "host": snis.XHTTP, "mode": "auto"}}),
                outbound("grpc", "grpc", ports.GRPC, snis.GRPC, map[string]any{
                        "grpcSettings": map[string]any{"serviceName": grpcService(), "multiMode": false}}),
        }

        return map[string]any{
                "log":       map[string]any{"loglevel": "warning"},
                "inbounds":  []map[string]any{{
                        "tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
                        "settings": map[string]any{"udp": true, "auth": "noauth"},
                        "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}}},
                "outbounds": append(links, map[string]any{"tag": "direct", "protocol": "freedom"}),
                "routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []map[string]any{
                        {"type": "field", "ip": []string{"geoip:private"}, "outboundTag": "direct"},
                        {"type": "field", "port": "0-65535", "outboundTag": "vision"},
                }},
        }
}

func flowFor(net string) string {
        if net == "tcp" {
                return "xtls-rprx-vision"
        }
        return ""
}

// geoLabel: short server location label for config names (e.g. "FRANKFURT").
func geoLabel() string {
        if g := serverGeoCached(); g != nil && g.City != "" {
                return strings.ToUpper(cityShort(g.City))
        }
        return "VPS"
}

func cityShort(city string) string {
        repl := map[string]string{
                "frankfurt am main": "Frankfurt", "london": "London", "paris": "Paris",
                "stockholm": "Stockholm", "amsterdam": "Amsterdam", "dublin": "Dublin",
        }
        lc := strings.ToLower(strings.TrimSpace(city))
        if v, ok := repl[lc]; ok {
                return v
        }
        return strings.TrimSpace(city)
}

// ─────────── /sub/<token> ───────────

func handleSub(w http.ResponseWriter, r *http.Request, tok string) {
        if tok == "" {
                sendBytes(w, 404, []byte("not found"), "text/plain; charset=utf-8", nil)
                return
        }
        tok = strings.SplitN(tok, "?", 2)[0]
        stateMu.RLock()
        var match *Client
        for _, c := range state.Clients {
                if constantTimeEq(subToken(c.ID), tok) {
                        cp := *c
                        match = &cp
                        break
                }
        }
        stateMu.RUnlock()
        if match == nil {
                sendBytes(w, 404, []byte("not found"), "text/plain; charset=utf-8", nil)
                return
        }

        host := requestHost(r)
        info := []string{fmt.Sprintf("upload=%d", match.Up), fmt.Sprintf("download=%d", match.Down)}
        if match.Quota > 0 {
                info = append(info, fmt.Sprintf("total=%d", match.Quota))
        }
        if match.ExpireAt > 0 {
                info = append(info, fmt.Sprintf("expire=%d", match.ExpireAt))
        }
        hdrs := map[string]string{
                "Profile-Title":           "base64:" + base64.StdEncoding.EncodeToString([]byte("DEEP NETWORK")),
                "Profile-Update-Interval": "6",
                "Subscription-Userinfo":   strings.Join(info, "; "),
                "X-Frame-Options":         "DENY",
        }

        switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("fmt"))) {
        case "json":
                links := buildLinks(match, host)
                var arr []map[string]string
                for _, l := range links {
                        arr = append(arr, map[string]string{"name": linkDisplayName(l), "url": l.URL})
                }
                b, _ := json.MarshalIndent(arr, "", "  ")
                sendBytes(w, 200, b, "application/json; charset=utf-8", hdrs)
        case "xray":
                cfg := clientConfigJSON(match, host)
                b, _ := json.MarshalIndent(cfg, "", "  ")
                sendBytes(w, 200, b, "application/json; charset=utf-8", hdrs)
        default:
                links := buildLinks(match, host)
                var lines []string
                for _, l := range links {
                        lines = append(lines, l.URL)
                }
                body := base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
                sendBytes(w, 200, []byte(body), "text/plain; charset=utf-8", hdrs)
        }
}
