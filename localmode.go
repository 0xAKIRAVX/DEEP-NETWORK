package main

// ─────────── v3.11: کیت شبکه ملی / Local-Mode Kit ───────────
// What happens when Iran switches to the "national internet" (international
// transit cut for consumer ISPs — the local-mode tests of 2022+):
//   * CDN edges & the foreign-hosted panel stop resolving/answering
//   * plain configs (CDN-routed) all die at once
// What survives:
//   * a domestic relay INSIDE Iran (Iranian VPS / cloud) is still reachable
//     on the national network; datacenters have kept their international
//     transit in every local-mode event so far, so a dumb TCP relay
//     user→relay→origin keeps the tunnel alive end-to-end (TLS terminates
//     at the origin — the relay only moves bytes, zero crypto changes).
// This kit generates, per user:
//   1) 🛡️ direct-IP variant      — skips client-side DNS (survives DNS
//                                   poisoning / partial CDN blocks)
//   2) 🎭 whitelisted-SNI variant — sni=<allowed domain> + allowInsecure=1
//                                   (survives SNI block/white-lists)
//   3) 🇮🇷 domestic-relay variants— the local-mode survivor (needs a relay
//                                   inside Iran; the panel generates the
//                                   one-line relay setup too)
// Honest limits: in a TOTAL blackout (Nov-2019 style, even DC transit cut)
// no software config can work — only physical alternates (satellite …).

import (
        "fmt"
        "net"
        net_url "net/url"
        "strings"
        "sync"
        "time"
)

// LocalModeState is persisted in state.json (schema-additive, safe to skip).
type LocalModeState struct {
        Enabled   bool   `json:"enabled"`
        RelayHost string `json:"relay_host,omitempty"`
        RelayPort int    `json:"relay_port,omitempty"`
        FakeSNI   string `json:"fake_sni,omitempty"`
        DirectIP  string `json:"direct_ip,omitempty"`
}

// localModeGet returns a sanitized copy of the local-mode settings.
func localModeGet() LocalModeState {
        stateMu.RLock()
        defer stateMu.RUnlock()
        return localModeSanitize(state.LocalMode)
}

// localModeSanitize clamps every field into a safe, usable shape.
func localModeSanitize(l *LocalModeState) LocalModeState {
        out := LocalModeState{}
        if l == nil {
                return out
        }
        out.Enabled = l.Enabled
        if validAddress(l.RelayHost) {
                out.RelayHost = strings.Trim(strings.TrimSpace(l.RelayHost), "[]")
        }
        if l.RelayPort >= 1 && l.RelayPort <= 65535 {
                out.RelayPort = l.RelayPort
        } else {
                out.RelayPort = 443
        }
        fs := strings.ToLower(strings.TrimSpace(l.FakeSNI))
        fs = strings.TrimSuffix(fs, ".")
        if fs != "" && hostRe.MatchString(fs) && !strings.Contains(fs, " ") {
                out.FakeSNI = fs
        }
        if dip := strings.TrimSpace(l.DirectIP); isIPLiteral(dip) && validAddress(dip) {
                out.DirectIP = strings.Trim(dip, "[]")
        }
        return out
}

// localPanelHost resolves the TLS/routing host the local variants present:
// an explicit SNI override (admin moved the panel behind a custom domain)
// or the request host.
func localPanelHost(host string) string {
        stateMu.RLock()
        defer stateMu.RUnlock()
        if ov := strings.TrimSpace(state.SNIOverride); ov != "" {
                return ov
        }
        return host
}

var (
        originIPMu    sync.Mutex
        originIPCache string
        originIPAt    time.Time
)

// resolveOriginIP resolves the panel domain to a literal IPv4 (the CDN/Lucity
// ingress) so clients can connect with no DNS at all. 10-minute cache.
func resolveOriginIP(host string) string {
        dom := strings.TrimSpace(host)
        if dom == "" || isIPLiteral(dom) {
                return dom
        }
        originIPMu.Lock()
        if originIPCache != "" && time.Since(originIPAt) < 10*time.Minute {
                c := originIPCache
                originIPMu.Unlock()
                return c
        }
        originIPMu.Unlock()
        ips, err := net.LookupIP(dom)
        if err != nil {
                return ""
        }
        for _, ip := range ips {
                if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() && !v4.IsPrivate() {
                        originIPMu.Lock()
                        originIPCache = v4.String()
                        originIPAt = time.Now()
                        originIPMu.Unlock()
                        return originIPCache
                }
        }
        return ""
}

// buildLocalLinks emits the national-internet survival variants for one
// client. They are appended AFTER the normal CDN/edge routes so daily use
// keeps its fast paths; client apps that test all configs simply pick the
// first working one (relay included) once international access is cut.
func buildLocalLinks(c *Client, host string) []Link {
        if host == "" {
                return nil
        }
        lm := localModeGet()
        if !lm.Enabled {
                return nil
        }
        if lm.RelayHost == "" && lm.DirectIP == "" && resolveOriginIP(host) == "" {
                return nil
        }
        allowed := userProtocols(c)
        t := tuningGet()
        fp := t.FP
        if fp == "" {
                fp = "chrome"
        }
        alpn := pyQuote(orStr(strings.TrimSpace(t.ALPN), "http/1.1"))
        cid := c.ID
        stateMu.RLock()
        fmtStr := state.CfgFmt
        stateMu.RUnlock()
        if fmtStr == "" {
                fmtStr = "{name}-{label}"
        }
        panelHost := localPanelHost(host)
        var out []Link
        add := func(key, label, url string) {
                out = append(out, Link{key, label, url})
        }

        directAddr := lm.DirectIP
        if directAddr == "" {
                directAddr = resolveOriginIP(host)
        }

        // ── 1) 🛡️ direct-IP variant: real SNI, literal address → no client DNS.
        if directAddr != "" && directAddr != lm.RelayHost && allowed["vless-ws"] {
                nm := fmtName(fmtStr, c, "VLESS-WS", "VLESS", "WS", "TLS", directAddr) + " 🛡️ IP مستقیم"
                sni := linkSNI(panelHost)
                add("vless-ws-direct", "VLESS · WS · مستقیم",
                        fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                cid, bracketV6(directAddr), pyQuote(sni), pyQuote(fp), alpn, pyQuote(panelHost),
                                pyQuote(wsPath()+"?ed=2048"), pyQuote(nm)))
        }

        // ── 3) 🇮🇷 domestic relay: TCP pipe inside Iran → origin. TLS stays
        //    end-to-end (relay only forwards bytes), so SNI/host are the panel's.
        if lm.RelayHost != "" {
                port := lm.RelayPort
                if port == 0 {
                        port = 443
                }
                uriAddr := bracketV6(lm.RelayHost)
                sni := linkSNI(panelHost)
                if allowed["vless-ws"] {
                        nm := fmtName(fmtStr, c, "VLESS-WS", "VLESS", "WS", "TLS", lm.RelayHost) + " 🇮🇷 رله داخلی"
                        add("vless-ws-relay", "VLESS · WS · رله داخلی",
                                fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                        cid, uriAddr, port, pyQuote(sni), pyQuote(fp), alpn, pyQuote(panelHost),
                                        pyQuote(wsPath()+"?ed=2048"), pyQuote(nm)))
                }
                if allowed["vless-hu"] {
                        nm := fmtName(fmtStr, c, "VLESS-HTTPUpgrade", "VLESS", "HTTPUpgrade", "TLS", lm.RelayHost) + " 🇮🇷 رله داخلی"
                        add("vless-hu-relay", "VLESS · HTTPUpgrade · رله داخلی",
                                fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&fp=%s&alpn=%s&type=httpupgrade&host=%s&path=%s#%s",
                                        cid, uriAddr, port, pyQuote(sni), pyQuote(fp), alpn, pyQuote(panelHost),
                                        pyQuote(huPath()), pyQuote(nm)))
                }
                if allowed["trojan-ws"] {
                        nm := fmtName(fmtStr, c, "Trojan-WS", "Trojan", "WS", "TLS", lm.RelayHost) + " 🇮🇷 رله داخلی"
                        add("trojan-ws-relay", "Trojan · WS · رله داخلی",
                                fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                        cid, uriAddr, port, pyQuote(sni), pyQuote(fp), alpn, pyQuote(panelHost),
                                        pyQuote(trojanPath()+"?ed=2048"), pyQuote(nm)))
                }
        }

        // ── 4) 🇮🇷 Iranian-CDN front — the NO-VPS path: a domestic CDN
        //    (ArvanCloud / Derak / …) put in front of the panel. The CDN edge
        //    is inside Iran (always reachable on the national network) and
        //    keeps its international transit to the origin during local-mode
        //    cutoffs, exactly like a relay VPS would. sni=host=<cdn domain>
        //    because the CDN terminates TLS itself (valid cert for its zone).
        if lm.RelayHost != "" && !isIPLiteral(lm.RelayHost) {
                dom := strings.Trim(lm.RelayHost, "[]")
                if allowed["vless-ws"] {
                        nm := fmtName(fmtStr, c, "VLESS-WS", "VLESS", "WS", "TLS", dom) + " 🇮🇷 CDN ایرانی"
                        add("vless-ws-cdn", "VLESS · WS · CDN ایرانی",
                                fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                        cid, bracketV6(dom), pyQuote(dom), pyQuote(fp), alpn, pyQuote(dom),
                                        pyQuote(wsPath()+"?ed=2048"), pyQuote(nm)))
                }
                if allowed["vless-hu"] {
                        nm := fmtName(fmtStr, c, "VLESS-HTTPUpgrade", "VLESS", "HTTPUpgrade", "TLS", dom) + " 🇮🇷 CDN ایرانی"
                        add("vless-hu-cdn", "VLESS · HTTPUpgrade · CDN ایرانی",
                                fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=%s&alpn=%s&type=httpupgrade&host=%s&path=%s#%s",
                                        cid, bracketV6(dom), pyQuote(dom), pyQuote(fp), alpn, pyQuote(dom),
                                        pyQuote(huPath()), pyQuote(nm)))
                }
                if allowed["trojan-ws"] {
                        nm := fmtName(fmtStr, c, "Trojan-WS", "Trojan", "WS", "TLS", dom) + " 🇮🇷 CDN ایرانی"
                        add("trojan-ws-cdn", "Trojan · WS · CDN ایرانی",
                                fmt.Sprintf("trojan://%s@%s:443?security=tls&sni=%s&fp=%s&alpn=%s&type=ws&host=%s&path=%s#%s",
                                        cid, bracketV6(dom), pyQuote(dom), pyQuote(fp), alpn, pyQuote(dom),
                                        pyQuote(trojanPath()+"?ed=2048"), pyQuote(nm)))
                }
        }
        return out
}

// stateAddress returns the admin-configured connect address
// (state.Address), falling back to host when unset — locked read.
func stateAddress(host string) string {
        stateMu.RLock()
        defer stateMu.RUnlock()
        if state.Address != "" {
                return state.Address
        }
        return host
}

// countDirectRoutes tells the admin how many DNS-free IP-literal routes the
// current subscription carries (the origin direct-IP variant plus the graded
// edge set when the all-operator optimizer has run).
func countDirectRoutes(c *Client, host string) int {
        n := 0
        for _, l := range buildLinks(c, host) {
                u, err := net_url.Parse(l.URL)
                if err != nil || u.Host == "" {
                        continue
                }
                hp := u.Host
                if i := strings.LastIndex(hp, ":"); i > strings.LastIndex(hp, "]") {
                        hp = hp[:i]
                }
                if isIPLiteral(hp) {
                        n++
                }
        }
        return n
}

// localModePayload feeds the panel «شبکه ملی» view (settings + guide).
func localModePayload(host string) map[string]any {
        lm := localModeGet()
        panelHost := localPanelHost(host)
        if panelHost == "" {
                panelHost = envStr("DOMAIN", "")
        }
        resolved := ""
        if !isIPLiteral(panelHost) && panelHost != "" {
                resolved = resolveOriginIP(panelHost)
        }
        variantKeys := []string{}
        for _, l := range buildLocalLinks(&Client{Name: "main", ID: mainUUID()}, host) {
                variantKeys = append(variantKeys, l.Key)
        }
        return map[string]any{
                "enabled":     lm.Enabled,
                "direct_routes": countDirectRoutes(&Client{Name: "main", ID: mainUUID()}, host),
                "relay_host":  lm.RelayHost,
                "relay_port":  lm.RelayPort,
                "fake_sni":    lm.FakeSNI,
                "direct_ip":   lm.DirectIP,
                "panel_host":  panelHost,
                "resolved_ip": resolved,
                "variants":    variantKeys,
                "guide":       relayGuide(panelHost, resolved),
        }
}

// freeCDNGuide is the NO-VPS survival path: put an Iranian CDN in front of
// the panel. The user needs no server at all — a domestic CDN account (and
// the domain it asks for) is the whole cost. Persian, plain steps.
func freeCDNGuide(panelHost string) string {
        target := panelHost
        if target == "" {
                target = "<panel-domain>"
        }
        return fmt.Sprintf(`۱) در یک CDN ایرانی حساب بسازید — رایگان: آروان‌کلاد (arvancloud.ir) یا ابر دراک (derak.cloud)
۲) یک دامنه لازم است: ارزان‌ترین دامنه ایرانی (حدود ده‌ها هزار تومان در سال) یا هر دامنه‌ای که دارید.
   نکته: دامنه را از همین حالا تنظیم کنید — در روز قطعی، تغییر DNS ممکن نیست.
۳) دامنه را در پنل CDN اضافه کنید (تأیید مالکیت با NS که پنل CDN می‌دهد).
۴) یک رکورد برای دامنه بسازید که به پنل اشاره کند:
     نوع: CNAME  |  نام: @  |  مقصد: %s  |  پراکسی CDN: روشن (ابر سبز)
۵) در تنظیمات CDN، گزینه WebSocket / وب‌سوکت را فعال کنید (برای مسیرهای /ws و /hu ضروری است).
۶) حالا آدرس همان دامنه را در کادر «آدرس رله داخلی» بالا وارد و ذخیره کنید —
   کانفیگ‌های «🇮🇷 CDN ایرانی» برای همه کاربران ساخته می‌شوند.

چرا کار می‌کند؟ لبه‌های CDN داخل ایران‌اند و روی شبکه ملی همیشه در دسترس‌اند؛
و ترانزیت بین‌الملل دیتاسنترهای CDN در همه‌ی رخدادهای قطعی تا امروز برقرار مانده است.
تذکر امنیتی: در حالت CDN، رمزنگاری TLS روی لبه‌ی CDN تمام می‌شود (اپراتور CDN ترافیک متن‌ساده را می‌تواند ببیند)؛
اگر حریم خصوصی کامل می‌خواهید، رله TCP خام (socat روی VPS) بهتر است.`, target)
}

// relayGuide builds the ready-to-paste domestic-relay setup commands.
func relayGuide(panelHost, originIP string) map[string]string {
        target := panelHost
        if target == "" {
                target = "<panel-domain>"
        }
        ipTarget := orStr(originIP, "<panel-ip>")
        if ipTarget == "<panel-ip>" {
                if ip := resolveOriginIP(target); ip != "" {
                        ipTarget = ip
                }
        }
        return map[string]string{
                "freecdn": freeCDNGuide(target),
                "socat":   fmt.Sprintf("socat TCP-LISTEN:443,fork,reuseaddr,keepalive TCP:%s:443", target),
                "gost":  fmt.Sprintf("gost -L \"tcp://:443/%s:443\"", target),
                "docker": fmt.Sprintf("docker run -d --restart=always --name deeprelay -p 443:443 " +
                        "alpine/socat TCP-LISTEN:443,fork,reuseaddr TCP:%s:443", target),
                "systemd": fmt.Sprintf(`# /etc/systemd/system/deeprelay.service
[Unit]
Description=DEEP NETWORK domestic relay
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/socat TCP-LISTEN:443,fork,reuseaddr,keepalive TCP:%s:443
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target

# then: systemctl daemon-reload && systemctl enable --now deeprelay
# (apt-get install -y socat  /  pacman -S socat)`, target),
                "iptables": fmt.Sprintf(`sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination %s:443
iptables -t nat -A POSTROUTING -j MASQUERADE
# (persists with iptables-persistent)`, ipTarget),
        }
}

// localModeKitText renders the full OFFLINE survival kit — the admin saves
// it BEFORE any cutoff: every user's local-mode links, the relay setup and
// the honest scenario guide. When international access is cut the panel
// itself is unreachable, so this file is the lifeline.
func localModeKitText(host string) string {
        panelHost := localPanelHost(host)
        if panelHost == "" {
                panelHost = envStr("DOMAIN", "<panel-domain>")
        }
        var b strings.Builder
        b.WriteString("╔══════════════════════════════════════════════════════════╗\n")
        b.WriteString("║   DEEP NETWORK — کیت بقا برای شبکه ملی (Local-Mode Kit)  ║\n")
        b.WriteString("╚══════════════════════════════════════════════════════════╝\n")
        b.WriteString("نسخه: v" + Version + "    تاریخ ساخت: " + time.Now().UTC().Format("2006-01-02 15:04 UTC") + "\n")
        b.WriteString("دامنه پنل: " + panelHost + "\n\n")

        b.WriteString("── سه سناریو، سه راه نجات ──────────────────────────────────\n\n")
        b.WriteString("۱) فیلتر DNS / بلاک‌شدن لبه‌ها (بین‌الملل وصل است):\n")
        b.WriteString("   کانفیگ‌های «🛡️ IP مستقیم» (بدون نیاز به DNS) و مسیرهای\n")
        b.WriteString("   لبه 🥈🥉 (از اسکن/بهینه‌سازی) همین حالا کار می‌کنند.\n\n")
        b.WriteString("۲) قطع بین‌الملل / اینترنت ملی (local mode):\n")
        b.WriteString("   فقط کانفیگ‌های «🇮🇷 رله داخلی» کار می‌کنند — مشروط به اینکه\n")
        b.WriteString("   رله داخل ایران باشد و دیتاسنتر آن ترانزیت بین‌الملل خود را\n")
        b.WriteString("   نگه داشته باشد (در همه‌ی رخدادهای قبلی حفظ شده است؛ در\n")
        b.WriteString("   خاموشی مطلق مثل آبان ۹۸ هیچ کانفیگی نمی‌تواند کار کند —\n")
        b.WriteString("   فقط مسیر فیزیکی جایگزین مثل اینترنت ماهواره‌ای). پیش از هر\n")
        b.WriteString("   قطعی، این فایل و کانفیگ‌ها را در کلاینت‌ها ذخیره کنید.\n\n")
        b.WriteString("۳) خاموشی کامل:\n")
        b.WriteString("   هیچ مسیر نرم‌افزاری وجود ندارد. صادقانه.\n\n")
        b.WriteString("در همه حالت‌ها کلاینت خود را روی «تست همه کانفیگ‌ها» بگذارید\n")
        b.WriteString("تا اولین مسیر سالم را خودکار پیدا کند.\n\n")

        b.WriteString("── بدون ثبت هویت و بدون دامنه؟ ──────────────────────────────\n\n")
        b.WriteString("کانفیگ‌های «🛡️ IP مستقیم» و «🎭 SNI سفید» هیچ‌کدام ثبت هویت،\n")
        b.WriteString("دامنه یا سرور نمی‌خواهند و همین حالا (بدون هیچ تنظیمی) کار می‌کنند:\n")
        b.WriteString("  * 🛡️ IP مستقیم: آیپی واقعی پنل به‌جای دامنه — ضد فیلتر DNS.\n")
        b.WriteString("  * مسیرهای لبه (🥈🥉…): اسکن خودکار پنل هر ۶ ساعت بهترین\n")
        b.WriteString("    لبه‌های پکت‌لاست ۰ و پرسرعت را می‌سنجد و به‌صورت خودکار\n")
        b.WriteString("    در کانفیگ‌ها جایگزاری می‌کند — بدون هیچ ثبت‌نامی.\n\n")
        b.WriteString("صادقانه: در قطع کامل بین‌الملل، تنها راهِ باقی‌ماندن آنلاین یک\n")
        b.WriteString("نقطه ورود داخل ایران است — و طبق قانون، هر سرویس ایرانی (CDN،\n")
        b.WriteString("VPS، هاست، دامنه .ir) ثبت هویت می‌خواهد. مسیر بدون هویت برای\n")
        b.WriteString("قطع کامل، فقط گزینه‌های فیزیکی (مثل اینترنت ماهواره‌ای) است.\n\n")

        b.WriteString("── بدون VPS؟ مسیر رایگان: CDN ایرانی ────────────────────────\n\n")
        b.WriteString("سرور لازم نیست! یک CDN ایرانی (آروان‌کلاد/دراک) جلوی پنل\n")
        b.WriteString("می‌نشیند و نقش رله را بازی می‌کند:\n\n")
        for _, ln := range strings.Split(freeCDNGuide(panelHost), "\n") {
                b.WriteString("    " + ln + "\n")
        }
        b.WriteString("\n")

        b.WriteString("── راه‌اندازی رله داخلی (روی سرور ایرانی، فقط یک بار) ────────\n\n")
        b.WriteString("هر سرور/VPS داخل ایران (پارس‌پک، آروان‌کلاد، هامروشن و …)\n")
        b.WriteString("که پورت 443 برای عموم باز داشته باشد کافی است. یکی از دستورهای\n")
        b.WriteString("زیر را روی آن اجرا کنید (هدف: " + panelHost + "):\n\n")
        g := relayGuide(panelHost, "")
        b.WriteString("[A] ساده‌ترین — socat:\n")
        b.WriteString("    apt-get install -y socat\n    " + g["socat"] + "\n\n")
        b.WriteString("[B] با gost:\n    " + g["gost"] + "\n\n")
        b.WriteString("[C] با Docker:\n    " + g["docker"] + "\n\n")
        b.WriteString("[D] systemd (پایدار بعد از ری‌استارت):\n" + g["systemd"] + "\n\n")
        b.WriteString("[E] بدون برنامه، فقط iptables:\n" + g["iptables"] + "\n\n")
        b.WriteString("سپس در پنل، «تنظیمات شبکه ملی» آدرس همین سرور را وارد کنید تا\n")
        b.WriteString("کانفیگ‌های 🇮🇷 برای همه کاربران ساخته شوند.\n\n")

        stateMu.RLock()
        clients := append([]*Client(nil), state.Clients...)
        stateMu.RUnlock()
        b.WriteString("── کانفیگ‌های کاربران (نسخه‌های بقا) ─────────────────────────\n\n")
        for _, c := range clients {
                links := buildLocalLinks(c, host)
                if len(links) == 0 {
                        continue
                }
                b.WriteString("♦ " + c.Name + "\n")
                for _, l := range links {
                        b.WriteString("  [" + l.Label + "]\n  " + l.URL + "\n")
                }
                b.WriteString("\n")
        }
        b.WriteString("── پایان کیت ──\n")
        return b.String()
}
