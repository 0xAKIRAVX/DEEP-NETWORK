package main

// ─────────── v3.24: خفن‌ترین بنر ترمینال ───────────
//
// The user's contract (2026-11-05):
//   «یه ظاهر خیلی خفن تو ترمینال براش درست کن (زمانی که پنل رو میخوام روی
//    ترمینال بیارم بالا) و میخوام رمز و پسورد رو تو صفحه ترمینال بهم بگه»
//
// What ships here:
//   * a gradient ASCII logo + rounded info box carrying the REAL panel URL
//     (http://IP:PORT on bare-IP VPS mode — fixes the old boot report that
//     always claimed https://DOMAIN), the username and the password,
//   * a scannable QR of the subscription URL printed in half-block glyphs
//     with explicit black-on-white ANSI (works on any terminal background),
//   * --banner / banner / -b CLI flag to re-print it any time
//     (`/opt/deep-network/out --banner`),
//   * engine/sweep status + Persian hints below the box (RTL text never goes
//     inside the box — alignment stays sane),
//   * colors auto-detected: real TTY, or systemd ($JOURNAL_STREAM, journalctl
//     renders ANSI), or FORCE_COLOR=1. QR only when colors are possible and
//     stdout is a TTY (piping QR without colors is unscannable garbage).

import (
        "fmt"
        "os"
        "strings"
)

// ── ANSI helpers ───────────────────────────────────────────────────

type termStyle struct{ on bool }

func (t termStyle) c(code string, s string) string {
        if !t.on {
                return s
        }
        return "\x1b[" + code + "m" + s + "\x1b[0m"
}

var bannerPalette = []string{"51", "50", "44", "38", "99", "135", "165", "200", "201", "213", "207", "75", "81"}

// ── the logo (ANSI-shadow) ─────────────────────────────────────────

var logoDeep = []string{
        "██████╗ ███████╗██████╗ ",
        "██╔══██╗██╔════╝██╔══██╗",
        "██║  ██║█████╗  ██████╔╝",
        "██║  ██║██╔══╝  ██╔══██╗",
        "██████╔╝███████╗██║  ██║",
        "╚═════╝ ╚══════╝╚═╝  ╚═╝",
}

var logoNetwork = []string{
        "███╗   ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ",
        "████╗  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗",
        "██╔██╗ ██║█████╗  ██║     █████╔╝ █████╗  ██████╔╝",
        "██║╚██╗██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗",
        "██║ ╚████║███████╗╚██████╗██║  ██╗███████╗██║  ██║",
        "╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
}

// ── environment detection ──────────────────────────────────────────

func stdoutIsTTY() bool {
        fi, err := os.Stdout.Stat()
        return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func bannerColorsOn() bool {
        if os.Getenv("FORCE_COLOR") != "" {
                return true
        }
        if stdoutIsTTY() {
                return true
        }
        // systemd sets $JOURNAL_STREAM on the service's stdout/stderr; journalctl
        // renders ANSI when viewed from a terminal (marzban/x-ui do the same).
        return os.Getenv("JOURNAL_STREAM") != ""
}

// panelBaseURL builds the REAL public URL of the panel. v3.24 bugfix: the
// old boot report always printed https://DOMAIN/panel — on a bare-IP VPS
// (DOMAIN=1.2.3.4, plain HTTP on :80/:8080) that URL is simply wrong.
func panelPublicURL() string {
        dom := strings.TrimSpace(osGetenv("DOMAIN"))
        if dom == "" && state != nil {
                stateMu.RLock()
                dom = strings.TrimSpace(state.Address)
                stateMu.RUnlock()
        }
        port := envInt("PORT", 8080)
        if dom == "" {
                return "http://localhost:" + itoa(port)
        }
        if isIPLiteral(dom) {
                if port == 80 {
                        return "http://" + dom
                }
                return "http://" + dom + ":" + itoa(port)
        }
        // domain mode rides a TLS-terminating CDN/proxy (Lucity, Caddy…)
        return "https://" + dom
}

// qrTerminal renders data as a scannable QR with half-block glyphs and an
// explicit black-on-white palette. Returns "" when it cannot be rendered.
func qrTerminal(data string, st termStyle) string {
        enc, err := qrEncode(data)
        if err != nil {
                return ""
        }
        mat := qrMatrix(enc.v, enc.level, enc.cws)
        n := len(mat)
        const quiet = 4
        size := n + 2*quiet
        cell := func(r, c int) bool {
                if r < quiet || c < quiet || r >= size-quiet || c >= size-quiet {
                        return false
                }
                return mat[r-quiet][c-quiet]
        }
        var sb strings.Builder
        for r := 0; r < size; r += 2 {
                line := strings.Builder{}
                for c := 0; c < size; c++ {
                        top, bot := cell(r, c), cell(r+1, c)
                        switch {
                        case top && bot:
                                line.WriteString("█")
                        case top:
                                line.WriteString("▀")
                        case bot:
                                line.WriteString("▄")
                        default:
                                line.WriteString(" ")
                        }
                }
                // dark modules: black glyphs on a white background — scannable on
                // every terminal, light or dark themed.
                sb.WriteString("      " + st.c("30;47", line.String()) + "\n")
        }
        return sb.String()
}

// visLen counts printable cells, skipping ANSI escape sequences (the box
// padding math must ignore color codes or the borders misalign).
func visLen(s string) int {
        n := 0
        inEsc := false
        for _, r := range s {
                if inEsc {
                        if r == 'm' {
                                inEsc = false
                        }
                        continue
                }
                if r == '\x1b' {
                        inEsc = true
                        continue
                }
                n++
        }
        return n
}

// bannerBox draws a box around key/value rows. All rows are plain ASCII
// (single width) so the padding math stays exact.
func bannerBox(st termStyle, rows []string) string {
        w := 0
        for _, r := range rows {
                if n := visLen(r); n > w {
                        w = n
                }
        }
        inner := w + 4
        var sb strings.Builder
        sb.WriteString("  " + st.c("36", strings.Repeat("─", inner+2)) + "\n")
        for _, r := range rows {
                pad := inner - visLen(r)
                sb.WriteString("  " + st.c("36", "│") + "  " + r + strings.Repeat(" ", pad) + st.c("36", "│") + "\n")
        }
        sb.WriteString("  " + st.c("36", strings.Repeat("─", inner+2)) + "\n")
        return sb.String()
}

// printBanner renders the full boot/banner display. forceQR is set by the
// --banner CLI flag (a human asked for it on purpose).
func printBanner(forceQR bool) {
        st := termStyle{on: bannerColorsOn()}
        user, pass := "", ""
        var clients []*Client
        if state != nil {
                stateMu.RLock()
                user = state.AdminUser
                pass = state.AdminPass
                clients = append(clients, state.Clients...)
                stateMu.RUnlock()
        }
        if user == "" {
                user = envStr("ADMIN_USER", "admin")
        }

        base := panelPublicURL()
        subURL := ""
        if id := mainUUID(); id != "" {
                subURL = base + "/sub/" + subToken(id)
        }
        if len(clients) > 0 && subURL == "" {
                subURL = base + "/sub/" + subToken(clients[0].ID)
        }

        // ── logo with a vertical gradient ──
        var sb strings.Builder
        sb.WriteString("\n")
        all := make([]string, 0, len(logoDeep)+1+len(logoNetwork))
        all = append(all, logoDeep...)
        all = append(all, "")
        all = append(all, logoNetwork...)
        for i, ln := range all {
                col := bannerPalette[i*len(bannerPalette)/len(all)]
                sb.WriteString("   " + st.c("1;"+col, ln) + "\n")
        }
        sb.WriteString("\n")

        // ── info box ──
        ipMode := isIPLiteral(strings.TrimSpace(osGetenv("DOMAIN")))
        rows := []string{
                st.c("1;36", "PANEL LOGIN"),
                "  URL        " + st.c("0", "│") + " " + st.c("1;32", base+"/panel"),
                "  Username   " + st.c("0", "│") + " " + st.c("1;37", user),
                "  Password   " + st.c("0", "│") + " " + st.c("1;33", pass),
                "",
                st.c("1;36", "SUBSCRIPTION  (v2rayNG / v2rayN)"),
        }
        if subURL != "" {
                rows = append(rows,
                        "  Link       "+st.c("0", "│")+" "+st.c("32", subURL),
                        "  Refresh    "+st.c("0", "│")+" "+st.c("32", "auto — every 1 minute"),
                )
        } else {
                rows = append(rows, "  (no client yet — add one in the panel)")
        }
        rows = append(rows, "")
        if tcpReady() {
                rows = append(rows, st.c("1;36", "TUNNEL  ·  VLESS + REALITY"))
                addr := tcpHost() + ":" + tcpPublicPort()
                rows = append(rows,
                        "  Address    "+st.c("0", "│")+" "+st.c("1;32", addr),
                        "  Public key "+st.c("0", "│")+" "+st.c("32", realityPub),
                        "  Short ID   "+st.c("0", "│")+" "+st.c("32", realitySID),
                        "  SNI        "+st.c("0", "│")+" "+st.c("32", realitySNI()),
                )
        } else {
                rows = append(rows, st.c("1;36", "TUNNEL"), "  (Reality link off — set TCP_HOST/TCP_PORT)")
        }
        eng := "  xray "
        if findXray() != "" {
                eng += st.c("1;32", "READY")
        } else {
                eng += st.c("1;31", "MISSING")
        }
        eng += "   probe "
        if deepProbeBin() != "" {
                eng += st.c("1;32", "READY")
        } else {
                eng += st.c("1;33", "go-fallback")
        }
        if sweepEnabled() {
                eng += "   sweep " + st.c("1;32", itoa(int(sweepEvery().Seconds()))+"s")
        }
        rows = append(rows, "", eng+"   v"+Version)
        sb.WriteString(bannerBox(st, rows))

        // ── QR of the subscription link (TTY only — see header) ──
        if subURL != "" && st.on && (stdoutIsTTY() || forceQR) {
                if qr := qrTerminal(subURL, st); qr != "" {
                        sb.WriteString("\n   " + st.c("1;36", "SCAN IN v2rayNG") + st.c("90", "  (subscription QR)") + "\n")
                        sb.WriteString(qr)
                }
        } else if subURL != "" && st.on {
                sb.WriteString("\n   " + st.c("90", "QR: run  /opt/deep-network/out --banner  in a terminal") + "\n")
        }

        // ── Persian hints (standalone lines only — RTL never enters the box) ──
        sb.WriteString("\n")
        if ipMode {
                sb.WriteString("   " + st.c("33", "آدرس پنل با http شروع می‌شود نه https — اگر مرورگر خودش به https برد، دستی http:// تایپ کن.") + "\n")
        }
        sb.WriteString("   " + st.c("90", "نمایش دوباره این صفحه:") + " " + st.c("1", "/opt/deep-network/out --banner") + "\n")
        sb.WriteString("   " + st.c("90", "اجرای پنل در ترمینال:") + " " + st.c("1", "sudo bash /opt/deep-network/run.sh") + "  " + st.c("90", "(Ctrl+C = توقف)") + "\n")
        sb.WriteString("   " + st.c("90", "لاگ زنده سرویس:") + " " + st.c("1", "journalctl -u deep-network -f") + "\n\n")

        fmt.Print(sb.String())
}

func realitySNI() string {
        if state != nil {
                stateMu.RLock()
                s := state.RealitySNI
                stateMu.RUnlock()
                if s != "" {
                        return s
                }
        }
        return "www.microsoft.com"
}
