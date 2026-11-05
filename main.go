package main

// ─────────────────────────────────────────────────────────────────────────────
// DEEP NETWORK v3.26 — VPS edition (Go, single static binary)
//   panel UI + API + subscriptions + Xray-core supervision
//   Inbounds: VLESS-Reality × { Vision (TCP), XHTTP, gRPC } — all on the VPS IP.
//   First visit → setup wizard (name, surname, photo → username, password).
// ─────────────────────────────────────────────────────────────────────────────

import (
        "crypto/sha256"
        "encoding/base64"
        "flag"
        "fmt"
        "net/http"
        "os"
        "os/signal"
        "strings"
        "syscall"
        "time"

        "golang.org/x/crypto/curve25519"
)

const Version = "3.26.0"

// ─────────── Reality keys (x25519, stable-derived from SECRET) ───────────

var (
        realityPriv string
        realityPub  string
        realitySID  string
)

func initReality() {
        priv := osGetenv("REALITY_PRIVATE_KEY")
        if priv == "" {
                seed := sha256.Sum256([]byte(secret() + ":reality"))
                priv = base64.RawURLEncoding.EncodeToString(seed[:])
        }
        var privBytes [32]byte
        if decoded, err := base64.RawURLEncoding.DecodeString(priv); err == nil && len(decoded) == 32 {
                copy(privBytes[:], decoded)
        } else if decoded, err := base64.StdEncoding.DecodeString(priv); err == nil && len(decoded) == 32 {
                copy(privBytes[:], decoded)
        } else {
                logf("WARNING: REALITY_PRIVATE_KEY invalid; deriving from SECRET")
                seed := sha256.Sum256([]byte(secret() + ":reality"))
                copy(privBytes[:], seed[:])
                priv = base64.RawURLEncoding.EncodeToString(seed[:])
        }
        pub, err := curve25519.X25519(privBytes[:], curve25519.Basepoint[:])
        if err != nil {
                logf("WARNING: could not derive the Reality public key; Reality disabled")
                return
        }
        realityPriv = priv
        realityPub = base64.RawURLEncoding.EncodeToString(pub)
        sid := osGetenv("REALITY_SHORT_ID")
        if !isValidHexSID(sid) {
                h := sha256.Sum256([]byte(secret() + ":sid"))
                sid = fmt.Sprintf("%x", h[:8])
        }
        realitySID = sid
}

func isValidHexSID(s string) bool {
        if len(s) == 0 || len(s)%2 != 0 || len(s) > 16 {
                return false
        }
        for i := 0; i < len(s); i++ {
                c := s[i]
                if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
                        return false
                }
        }
        return true
}

// ─────────── loops ───────────

func watchdogLoop() {
        lastPrune := time.Now()
        for {
                time.Sleep(4 * time.Second)
                if !xrayRunning() {
                        logf("xray exited — restarting")
                        restartXray()
                }
                if time.Since(lastPrune) > 5*time.Minute {
                        pruneSessions()
                        lastPrune = time.Now()
                }
        }
}

// ─────────── boot report / --banner ───────────

func bannerText() string {
        host := publicHost()
        line := strings.Repeat("─", 64)
        var b strings.Builder
        b.WriteString(line + "\n")
        b.WriteString(fmt.Sprintf("  DEEP NETWORK v%s  (VPS edition)\n", Version))
        b.WriteString(line + "\n")
        b.WriteString(fmt.Sprintf("  panel     : http://%s/panel\n", host))
        claimed := profileClaimed()
        if !claimed {
                b.WriteString("\n  ⚠  حساب مدیر هنوز ساخته نشده است.\n")
                b.WriteString("     لینک بالا را در مرورگر باز کن و اولین صفحه (ثبت نام و نام\n")
                b.WriteString("     و نام خانوادگی و عکس) را کامل کن تا پنل مال تو شود.\n\n")
                b.WriteString("     اولین نفری که فرم را پر کند مالک پنل می‌شود — همین حالا باز کن.\n")
        } else {
                stateMu.RLock()
                user := state.Profile.User
                first, last := state.Profile.First, state.Profile.Last
                stateMu.RUnlock()
                b.WriteString(fmt.Sprintf("  owner     : %s %s (@%s)\n", first, last, user))
                b.WriteString(fmt.Sprintf("  username  : %s\n", user))
        }
        // transports
        ports := effectivePorts()
        snis := effectiveSNIs()
        b.WriteString("\n  transports (VLESS · Reality):\n")
        b.WriteString(fmt.Sprintf("    Vision  : %s:%-5d  (SNI %s, flow xtls-rprx-vision)\n", host, ports.Vision, snis.Vision))
        b.WriteString(fmt.Sprintf("    XHTTP   : %s:%-5d  (SNI %s, path %s)\n", host, ports.XHTTP, snis.XHTTP, xhttpPath()))
        b.WriteString(fmt.Sprintf("    gRPC    : %s:%-5d  (SNI %s, service %s)\n", host, ports.GRPC, snis.GRPC, grpcService()))
        // subscriptions
        subs := subList()
        if len(subs) > 0 {
                b.WriteString("\n  subscriptions:\n")
                for i, s := range subs {
                        if i >= 5 {
                                b.WriteString(fmt.Sprintf("    … and %d more (see panel)\n", len(subs)-5))
                                break
                        }
                        b.WriteString(fmt.Sprintf("    [%s] http://%s/sub/%s\n", firstN(s.name, 14), host, s.token))
                }
                if len(subs) > 0 {
                        u := fmt.Sprintf("http://%s/sub/%s", host, subs[0].token)
                        if qr, err := qrASCII(u, 2); err == nil {
                                b.WriteString("\n" + qr + "\n")
                                b.WriteString("    ^ scan in v2rayNG → subscription → scan QR\n")
                        }
                }
        }
        if cc, ok := sysctlStatus(); ok {
                _ = cc
                b.WriteString("\n  speed     : BBR + fq + 32MB buffers ACTIVE\n")
        } else {
                b.WriteString("\n  speed     : sysctl tuning unavailable (run as root for BBR)\n")
        }
        b.WriteString(line + "\n")
        return b.String()
}

func bootReport() {
        host := publicHost()
        line := strings.Repeat("─", 62)
        logf("%s", line)
        logf("DEEP NETWORK %s is up (VPS edition)", Version)
        logf("  panel     : http://%s/panel", host)
        if !profileClaimed() {
                logf("  setup     : OPEN — first visit claims the panel (name, photo, username, password)")
        } else {
                stateMu.RLock()
                logf("  owner     : %s %s (@%s)", state.Profile.First, state.Profile.Last, state.Profile.User)
                stateMu.RUnlock()
        }
        p := effectivePorts()
        s := effectiveSNIs()
        logf("  Vision    : port %d  (SNI %s)", p.Vision, s.Vision)
        logf("  XHTTP     : port %d  (SNI %s, path %s)", p.XHTTP, s.XHTTP, xhttpPath())
        logf("  gRPC      : port %d  (SNI %s, service %s)", p.GRPC, s.GRPC, grpcService())
        logf("  xray      : %s", orStr(b2s(ensureXray() != ""), "MISSING — Reality stays off"))
        if _, ok := sysctlStatus(); ok {
                logf("  speed     : BBR + fq + big buffers ACTIVE")
        } else {
                logf("  speed     : sysctl tuning not applied (not root?)")
        }
        logf("  data dir  : %s", dataDir())
        logf("%s", line)
}

func b2s(b bool) string {
        if b {
                return "ok"
        }
        return ""
}

// ─────────── main ───────────

func main() {
        banner := flag.Bool("banner", false, "print panel info, subscriptions and QR, then exit")
        ver := flag.Bool("version", false, "print version")
        doReset := flag.Bool("reset-pass", false, "reset the admin account to unclaimed (setup wizard shows on next visit)")
        doDoctor := flag.Bool("doctor", false, "run the end-to-end self-test through all transports, then exit")
        flag.Parse()

        if *ver {
                fmt.Println("DEEP NETWORK " + Version + " (VPS edition)")
                return
        }

        loadState()
        initReality()
        loadOfflineLog()

        if *doReset {
                resetProfile()
                fmt.Println("OK — admin account cleared. Open the panel link to run the setup wizard again.")
                return
        }

        ensureXray()
        xrayMu.Lock()
        spawnXrayLocked()
        xrayMu.Unlock()

        applySysctls() // BBR + fq + buffers — self-heal on every boot (root only)

        if *banner {
                fmt.Print(bannerText())
                return
        }
        if *doDoctor {
                res := doctorRun()
                for _, d := range res {
                        st := "FAIL"
                        if d.OK {
                                st = fmt.Sprintf("OK %dms", d.MS)
                        }
                        fmt.Printf("  %-22s %s %s\n", d.Name, st, d.Err)
                }
                return
        }

        go samplerLoop()
        go watchdogLoop()
        go sessionLoop()
        go serverGeo()
        go doctorLoop()

        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
        go func() {
                <-sig
                logf("shutting down...")
                xrayMu.Lock()
                if xrayCmd != nil && xrayCmd.Process != nil {
                        _ = xrayCmd.Process.Signal(syscall.SIGTERM)
                }
                xrayMu.Unlock()
                os.Exit(0)
        }()

        bootReport()

        port := envInt("PORT", 80)
        if err := startServer(port); err != nil {
                logf("FATAL: %v", err)
                os.Exit(1)
        }
        _ = http.StatusOK
}
