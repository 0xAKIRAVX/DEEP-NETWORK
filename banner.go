package main

// ─────────── v3.24: the terminal banner (Task 50) ───────────
// "یه ظاهر خیلی خفن تو ترمینال + رمز و پسورد تو صفحه ترمینال":
// a colored ASCII banner at boot that shows the panel URL, the ADMIN
// USERNAME + PASSWORD (always — that is the point), the subscription URLs
// and, on color terminals, a scannable QR of the main sub URL so v2rayNG
// can import it straight off the screen. When stdout is the systemd
// journal (not a TTY) the ANSI codes are dropped so `journalctl -u` stays
// clean, but every value is still printed.

import (
        "fmt"
        "os"
        "strings"
)

// ── color plumbing ──

func stdoutIsTTY() bool {
        st, err := os.Stdout.Stat()
        if err != nil {
                return false
        }
        return st.Mode()&os.ModeCharDevice != 0
}

// colorsOn: real terminal (or FORCE_COLOR) AND NO_COLOR unset AND not the
// raw journal stream.
func colorsOn() bool {
        if os.Getenv("FORCE_COLOR") != "" {
                return true // explicit override wins, even over NO_COLOR
        }
        if os.Getenv("NO_COLOR") != "" {
                return false
        }
        return stdoutIsTTY() && os.Getenv("JOURNAL_STREAM") == ""
}

var (
        cReset  = ""
        cBorder = ""
        cLogo1  = ""
        cLogo2  = ""
        cLabel  = ""
        cValue  = ""
        cURL    = ""
        cPass   = ""
        cWarn   = ""
        cDim    = ""
)

func initBannerColors() {
        if !colorsOn() {
                return
        }
        cReset = "\033[0m"
        cBorder = "\033[38;5;51m"  // bright cyan
        cLogo1 = "\033[38;5;87m"   // aqua
        cLogo2 = "\033[38;5;213m"  // orchid
        cLabel = "\033[1;38;5;45m" // bold cyan
        cValue = "\033[1;37m"      // bold white
        cURL = "\033[1;38;5;82m"   // bold bright green
        cPass = "\033[1;38;5;226m" // bold bright yellow
        cWarn = "\033[1;38;5;203m" // bold salmon
        cDim = "\033[38;5;245m"    // gray
}

// bannerKV renders one `LABEL .... value` row inside the box. Values that
// don't fit are middle-truncated so the border always lines up.
func bannerKV(label, value, valueColor string, width int) string {
        vc := valueColor
        if vc == "" {
                vc = cValue
        }
        max := width - 2 - 11 - 3
        if r := []rune(stripANSI(value)); runeLen(value) > max && max > 4 {
                value = string(r[:max/2-1]) + "…" + string(r[len(r)-(max-max/2):])
        }
        gap := width - 2 - 11 - runeLen(value)
        if gap < 1 {
                gap = 1
        }
        return cBorder + "║  " + cLabel + padTo(label, 11) + vc + value + strings.Repeat(" ", gap) + cBorder + "║"
}

// bannerSep: "╠═════ text ═══════╣" with the fill computed from the real
// rune length (Persian text included) so the right border always lines up.
func bannerSep(text string, width int) string {
        fill := width - 4 - runeLen(text)
        if fill < 0 {
                fill = 0
        }
        left := fill / 2
        right := fill - left
        return cBorder + "╠" + strings.Repeat("═", left+1) + " " + cLabel + text + cReset + " " + cBorder + strings.Repeat("═", right+1) + "╣"
}

func runeLen(s string) int { return len([]rune(stripANSI(s))) }

func stripANSI(s string) string {
        if !strings.Contains(s, "\033[") {
                return s
        }
        var b strings.Builder
        inEsc := false
        for _, r := range s {
                if inEsc {
                        if r == 'm' {
                                inEsc = false
                        }
                        continue
                }
                if r == '\033' {
                        inEsc = true
                        continue
                }
                b.WriteRune(r)
        }
        return b.String()
}

func padTo(s string, n int) string {
        if len(s) >= n {
                return s + " "
        }
        return s + strings.Repeat(" ", n-len(s))
}

// centerRow: one centered plain-text row inside the box.
func centerRow(text string, width int) string {
        fill := width - 1 - runeLen(text)
        if fill < 0 {
                fill = 0
        }
        left := fill / 2
        return cBorder + "║ " + strings.Repeat(" ", left) + text + strings.Repeat(" ", fill-left) + cBorder + "║"
}

// qrTerm renders a scannable QR (half-block UTF-8, dark modules as ink)
// or "" when the data does not fit / colors are off (journal gets URLs).
func qrTerm(data string, W int) string {
        if !colorsOn() || len(data) > 900 {
                return ""
        }
        enc, err := qrEncode(data)
        if err != nil {
                return ""
        }
        m := qrMatrix(enc.v, enc.level, enc.cws)
        n := len(m)
        qz := 2 // quiet zone modules
        size := n + qz*2
        // half-block rendering: ONE character per module, two module rows per
        // text line (terminal cells are ~2:1 tall, so modules come out square).
        // idx: 0 blank · 1 bottom ink · 2 top ink · 3 full ink.
        ink := [4]rune{' ', '▄', '▀', '█'}
        lead := (W - size) / 2
        if lead < 1 {
                lead = 1
        }
        trail := W - size - lead
        // paper AND ink are both set explicitly so the QR scans on light AND
        // dark terminals (the ink glyphs must not fall back to the default bg).
        paper := "\x1b[48;5;231m"             // white background
        inkc := "\x1b[48;5;231m\x1b[38;5;16m" // white bg + black ink glyph
        var rows []string
        for y := 0; y < (size+1)/2; y++ {
                var b strings.Builder
                b.WriteString(cBorder + "║" + strings.Repeat(" ", lead))
                for x := 0; x < size; x++ {
                        top, bot := false, false
                        if ty := y*2 - qz; ty >= 0 && ty < n && x-qz >= 0 && x-qz < n {
                                top = m[ty][x-qz]
                        }
                        if by := y*2 + 1 - qz; by >= 0 && by < n && x-qz >= 0 && x-qz < n {
                                bot = m[by][x-qz]
                        }
                        idx := 0
                        if top {
                                idx += 2
                        }
                        if bot {
                                idx++
                        }
                        if idx == 0 {
                                b.WriteString(paper + " ")
                        } else {
                                b.WriteString(inkc + string(ink[idx]))
                        }
                }
                b.WriteString(cReset + strings.Repeat(" ", trail) + cBorder + "║")
                rows = append(rows, b.String())
        }
        return strings.Join(rows, "\n")
}

// ── the boot banner ──

var bannerLogo = []string{
        ` ██████╗  ██████╗██████╗ ███████╗███╗   ██╗████████╗██╗  ██╗   ██╗`,
        ` ██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║  ╚██╗ ██╔╝`,
        ` ██║  ██║██║     ██████╔╝█████╗  ██╔██╗ ██║   ██║   ██║   ╚████╔╝ `,
        ` ██║  ██║██║     ██╔══██╗██╔══╝  ██║╚██╗██║   ██║   ██║    ╚██╔╝  `,
        ` ██████╔╝╚██████╗██║  ██║███████╗██║ ╚████║   ██║   ███████╗██║   `,
        ` ╚═════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝   `,
}

// bootBanner is the v3.24 replacement of the plain bootReport — same facts,
// far cooler shell, credentials front and center.
func bootBanner() {
        initBannerColors()
        const W = 76

        stateMu.RLock()
        user := state.AdminUser
        pw := state.AdminPass
        clients := append([]*Client(nil), state.Clients...)
        stateMu.RUnlock()

        // panel + sub URLs, deployment-aware
        var panelAddr, subAddr string
        if vpsMode() {
                panelAddr = subURLScheme() + "://" + vpsPanelHost() + "/panel"
                if len(clients) > 0 {
                        subAddr = subURLScheme() + "://" + vpsPanelHost() + "/sub/" + subToken(clients[0].ID)
                }
        } else {
                dom := strings.TrimSpace(os.Getenv("DOMAIN"))
                if dom == "" {
                        dom = "<your-domain>"
                }
                panelAddr = "https://" + dom + "/panel"
                if len(clients) > 0 {
                        subAddr = "https://" + dom + "/sub/" + subToken(clients[0].ID)
                }
        }

        out := &strings.Builder{}
        fmt.Fprintln(out, cBorder+"╔"+strings.Repeat("═", W)+"╗")
        for i, ln := range bannerLogo {
                c := cLogo1
                if i >= 3 {
                        c = cLogo2
                }
                pad := W - 1 - runeLen(ln)
                if pad < 0 {
                        pad = 0
                }
                fmt.Fprintln(out, cBorder+"║ "+c+ln+strings.Repeat(" ", pad)+cBorder+"║")
        }
        fmt.Fprintln(out, centerRow(cValue+"DEEP NETWORK"+cReset+"  "+cDim+"v"+Version+cReset, W))
        fmt.Fprintln(out, bannerSep("PANEL LOGIN · ورود به پنل", W))
        fmt.Fprintln(out, bannerKV("PANEL", panelAddr, cURL, W))
        fmt.Fprintln(out, bannerKV("USERNAME", user, cValue, W))
        fmt.Fprintln(out, bannerKV("PASSWORD", pw, cPass, W))
        fmt.Fprintln(out, bannerKV("VERSION", "v"+Version+"  (Go + Rust edition)", cDim, W))

        if subAddr != "" {
                fmt.Fprintln(out, bannerSep("SUBSCRIPTION · لینک ساب", W))
                fmt.Fprintln(out, bannerKV("SUB URL", subAddr, cURL, W))
                if len(clients) > 1 {
                        fmt.Fprintln(out, bannerKV("+ USERS", fmt.Sprintf("%d کاربر دیگر — لینک هرکدام در پنل", len(clients)-1), cDim, W))
                }
        }

        // Reality endpoint (VPS: THE row; CDN: shown when the proxy is wired).
        if vpsMode() {
                fmt.Fprintln(out, bannerSep("REALITY · سریع‌ترین مسیر", W))
                fmt.Fprintln(out, bannerKV("REALITY", fmt.Sprintf("%s:%d  (VLESS Vision · بدون دامنه)", vpsRealityAddr(), vpsRealityPort()), cURL, W))
                // v3.25: the XHTTP + gRPC transports ride their own ports.
                if ep := computeVpsExtraPorts(realityVariants(vpsRealityPort())); ep.xhttp > 0 || ep.grpc > 0 {
                        xg := ""
                        if ep.xhttp > 0 {
                                xg += fmt.Sprintf("xhttp:%d", ep.xhttp)
                        }
                        if ep.grpc > 0 {
                                if xg != "" {
                                        xg += "  "
                                }
                                xg += fmt.Sprintf("grpc:%d", ep.grpc)
                        }
                        fmt.Fprintln(out, bannerKV("XHTTP/gRPC", xg+"  (همان کلید Reality)", cURL, W))
                }
                fmt.Fprintln(out, bannerKV("FALLBACK", fmt.Sprintf("ws/hu روی پورت %d (اگر ۴۴۳ فیلتر شد)", panelPublicPort()), cDim, W))
        } else if tcpHost() != "" && tcpPublicPort() != "" {
                fmt.Fprintln(out, bannerSep("REALITY · TCP", W))
                fmt.Fprintln(out, bannerKV("TCP PROXY", tcpHost()+":"+tcpPublicPort(), cURL, W))
        }

        // QR of the sub URL — scan with v2rayNG right off the terminal.
        if qr := qrTerm(subAddr, W); qr != "" {
                fmt.Fprintln(out, bannerSep("SUB QR · اسکن کن", W))
                fmt.Fprintln(out, qr)
        }

        // runtime facts
        fmt.Fprintln(out, bannerSep("RUNTIME · وضعیت", W))
        if vpsMode() {
                fmt.Fprintln(out, bannerKV("MODE", "VPS مستقیم (بدون CDN) — ساب روی http", cDim, W))
        }
        fmt.Fprintln(out, bannerKV("ENGINE", "xray="+orStr(b2s(ensureXray() != ""), "missing")+
                "  deep-probe="+orStr(b2s(deepProbeBin() != ""), "go-fallback"), cDim, W))
        if dataDir() == "/tmp" {
                msg := "⚠ state is EPHEMERAL — /data not writable"
                fmt.Fprintln(out, cBorder+"║  "+cWarn+msg+strings.Repeat(" ", W-2-runeLen(msg))+cBorder+"║")
        } else {
                fmt.Fprintln(out, bannerKV("DATA DIR", dataDir()+" (persistent)", cDim, W))
        }
        if sweepEnabled() && !vpsMode() {
                fmt.Fprintln(out, bannerKV("SWEEP", fmt.Sprintf("هر %ds — لبه مرده/کند حذف و جایگزین", int(sweepEvery().Seconds())), cDim, W))
        }
        fmt.Fprintln(out, cBorder+"╚"+strings.Repeat("═", W)+"╝")

        // one blank line then the whole banner in a single write (atomic look)
        logf("%s", out.String())
}
