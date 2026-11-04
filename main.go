package main

import (
        "crypto/sha256"
        "encoding/base64"
        "fmt"
        "net"
        "net/http"
        "os"
        "os/signal"
        "strings"
        "syscall"
        "time"

        "golang.org/x/crypto/curve25519"
)

// ─────────── DEEP NETWORK v3 — Go + Rust rewrite ───────────
// Single static binary: panel UI + API + subscriptions + tunnel proxy
// (nginx eliminated; xray-core supervised as a child process).

const Version = "3.25.0"

// ─────────── Reality keys (x25519 derived from SECRET) ───────────

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
                logf("WARNING: REALITY_PRIVATE_KEY is not a valid 32-byte key; deriving from SECRET")
                seed := sha256.Sum256([]byte(secret() + ":reality"))
                copy(privBytes[:], seed[:])
                priv = base64.RawURLEncoding.EncodeToString(seed[:])
        }
        pub, err := curve25519.X25519(privBytes[:], curve25519.Basepoint[:])
        if err != nil {
                logf("WARNING: could not derive the Reality public key; TCP link disabled")
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

func watchdogLoop() {
        lastPrune := time.Now()
        for {
                time.Sleep(4 * time.Second)
                if !xrayRunning() {
                        logf("xray exited - restarting")
                        restartXray()
                }
                if time.Since(lastPrune) > 5*time.Minute {
                        pruneSessions()
                        lastPrune = time.Now()
                }
        }
}

func usageLoop() {
        // v3.10: superseded by sessionLoop (2s sampling of the Xray user
        // counters feeding the online monitor + the same 30s housekeeping).
        sessionLoop()
}

func b2s(b bool) string {
        if b {
                return "ok"
        }
        return ""
}

func resolveHost(h string) []string {
        ips, err := net.LookupIP(h)
        if err != nil {
                return nil
        }
        var out []string
        for _, ip := range ips {
                if v4 := ip.To4(); v4 != nil {
                        out = append(out, v4.String())
                }
        }
        return out
}

func httpClientGet(u string) (*http.Response, error) {
        c := http.Client{Timeout: 180 * time.Second}
        req, err := http.NewRequest("GET", u, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set("User-Agent", "DeepNetwork/"+Version)
        return c.Do(req)
}

// ─────────── main ───────────

func main() {
        sig := make(chan os.Signal, 1)
        signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

        // v3.24: `deep-network --banner` — print the boot banner (panel URL,
        // credentials, sub URL, QR) and exit. install.sh / run.sh surface it so
        // the admin can always recover the password from the terminal.
        if len(os.Args) > 1 && (os.Args[1] == "--banner" || os.Args[1] == "banner") {
                loadState()
                initReality()
                bootBanner()
                return
        }

        loadState()
        initReality()
        loadOfflineLog()

        ensureXray()
        // v3.24: probe the Reality-variant ports NOW, before xray binds them —
        // later probes would see our own listeners and drop the variants.
        // v3.25: same for the XHTTP/gRPC transport ports.
        if vpsMode() {
                computeVpsExtraPorts(computeRealityVariants(vpsRealityPort()))
        }
        xrayMu.Lock()
        spawnXrayLocked()
        xrayMu.Unlock()

        refreshProxyRoutes()
        go samplerLoop()
        go watchdogLoop()
        go usageLoop()
        go serverGeo()
        // v3.25: the CDN machinery (edge autoscan, minute sweep, SNI-front
        // watcher, edge pre-warm) is dead weight on a self-hosted VPS —
        // there are no bunny edges to scan there. Skipped entirely.
        if !vpsMode() {
                go autoScanLoop()   // v3.14: scan & apply best edges automatically
                go sweepLoop()      // v3.23: per-minute health pass — prune dead/slow edges, keep the sub fresh
                go frontWatchLoop() // v3.17: re-check the active SNI front from Iran every 15 min, self-heal
        }
        go lockWatchdog()   // v3.16: a frozen state lock dumps stacks + self-restarts

        // v3.5: Telegram install bot (optional — activated by INSTALL_BOT_TOKEN).
        // Deploys new DEEP NETWORK panels on requesters' own Lucity accounts.
        // v3.5.2: the watchdog restarts the poll loop if it ever goes stale, so
        // the bot can never silently stop answering users.
        if tok := strings.TrimSpace(osGetenv("INSTALL_BOT_TOKEN")); tok != "" {
                go installBotLoop(tok)
                go ibotWatchdog(tok)
        }

        // v3.3→v3.25: pre-warm the CDN edge list — CDN deploys only (a VPS
        // has no bunny edges; the goroutine was pure wasted work there).
        if !vpsMode() {
                go func() {
                        time.Sleep(15 * time.Second)
                        dom := strings.TrimSpace(osGetenv("DOMAIN"))
                        if dom == "" {
                                dom = "deep-network-development-w4a86.lucity.app"
                        }
                        if dom != "" && !isIPLiteral(dom) {
                                logf("pre-warming CDN edge cache for %s (v4+v6) …", dom)
                                bunnyEdgesFor(dom, "4")
                                logf("CDN edge cache ready (IPv4)")
                                go func() {
                                        bunnyEdgesFor(dom, "6")
                                        logf("CDN edge cache ready (IPv6)")
                                }()
                        }
                }()
        }

        bootBanner()

        port := envInt("PORT", 8080)
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

        if err := startServer(port); err != nil {
                logf("FATAL: %v", err)
                os.Exit(1)
        }
}
