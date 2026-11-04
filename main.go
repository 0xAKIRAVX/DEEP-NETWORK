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

// ─────────── boot report (zero-variable deployment) ───────────

func bootReport() {
	// v3.24: identity (URL / credentials / sub / tunnel) moved into the
	// terminal banner — the old lines here always claimed https://DOMAIN
	// which is wrong on a bare-IP VPS (plain http://IP:PORT).
	printBanner(false)
	stateMu.RLock()
	front := state.FrontSNI
	hours := state.AutoScanHours
	autoScanOn := state.AutoScan
	stateMu.RUnlock()
	if hours < 1 || hours > 24 {
		hours = 1
	}
	logf("  autoscan   : every %dh (best 0-loss edges auto-applied into configs)", hours)
	if front != "" {
		logf("  SNI front  : %s active (links hide the panel domain from the wire)", front)
	} else {
		logf("  SNI front  : pending first scan (bunny shared-cert front, proven before use)")
	}
	if dom := strings.TrimSpace(osGetenv("DOMAIN")); dom != "" && !isIPLiteral(dom) {
		logf("  anti-SNI   : random-subdomain SNI is ON for *.lucity.app links")
		logf("               (Settings can disable it); sub-130ms ping: IP Scanner ->")
		logf("               scan CDN edges, apply the nearest (Turkey/Azerbaijan/Iraq).")
	}
	logf("  watchdog   : ON — a frozen state lock dumps stacks and self-restarts")
	if autoScanOn {
		logf("  auto-scan : ON — panel scans & applies 0-loss edges every %dh + doctor self-test", hours)
	}
	if sweepEnabled() {
		logf("  minute-sweep: ON — every %ds: dead (TLS-fail) and >%dms edges pruned & replaced, auto address self-heals",
			int(sweepEvery().Seconds()), sweepPingMs())
	}
	if lm := localModeGet(); lm.Enabled {
		logf("  local-mode : kit ON — survival variants ride every subscription")
		if lm.RelayHost != "" {
			logf("               relay %s:%d (domestic) + direct + white-SNI variants", lm.RelayHost, lm.RelayPort)
		} else {
			logf("               direct-IP + white-SNI variants (no relay configured)")
		}
		logf("               panel view: شبکه ملی — save the offline kit BEFORE a cutoff.")
	}
	if dataDir() == "/tmp" {
		logf("  WARNING   : state is EPHEMERAL - /data is not writable.")
		logf("               Attach a volume at /data so users & links survive redeploys.")
	} else {
		logf("  data dir  : %s (persistent)", dataDir())
	}
	if osGetenv("INSTALL_BOT_TOKEN") != "" {
		logf("  install bot: ON — anyone can get their own panel via Telegram")
	}
	tcpStat := "not configured - Reality link stays off"
	if tcpHost() != "" && tcpPublicPort() != "" {
		tcpStat = ""
	}
	logf("  TCP proxy : app port %d, public %s:%s %s", tcpAppPort(), orStr(tcpHost(), "-"),
		orStr(tcpPublicPort(), "-"), tcpStat)
	logf("  engine    : xray=%s deep-probe=%s", orStr(b2s(ensureXray() != ""), "missing"),
		orStr(b2s(deepProbeBin() != ""), "missing (Go fallback active)"))
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
	// v3.24: --banner re-prints the terminal banner (logo + credentials +
	// sub URL + QR) without starting anything. --version prints the version.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--banner", "-b", "banner":
			loadState()
			initReality()
			printBanner(true)
			os.Exit(0)
		case "--version", "-v", "version":
			fmt.Printf("deep-network %s\n", Version)
			os.Exit(0)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	loadState()
	initReality()
	loadOfflineLog()

	ensureXray()
	xrayMu.Lock()
	spawnXrayLocked()
	xrayMu.Unlock()

	refreshProxyRoutes()
	go samplerLoop()
	go watchdogLoop()
	go usageLoop()
	go serverGeo()
	go autoScanLoop()   // v3.14: scan & apply best edges automatically
	go sweepLoop()      // v3.23: per-minute health pass — prune dead/slow edges, keep the sub fresh
	go frontWatchLoop() // v3.17: re-check the active SNI front from Iran every 15 min, self-heal
	go lockWatchdog()   // v3.16: a frozen state lock dumps stacks + self-restarts
	// v3.25: periodic self-test. On a bare-IP VPS there is no autoscan and
	// no sweep material (no CDN edges), so without this loop the doctor
	// would never prove the Reality tunnel — the one transport the VPS
	// ships. Verdict lands in state.Doctor + the log ("doctor: …").
	go func() {
		time.Sleep(25 * time.Second)
		for {
			if doctorRun() {
				time.Sleep(15 * time.Minute)
			} else {
				time.Sleep(5 * time.Minute)
			}
		}
	}()

	// v3.5: Telegram install bot (optional — activated by INSTALL_BOT_TOKEN).
	// Deploys new DEEP NETWORK panels on requesters' own Lucity accounts.
	// v3.5.2: the watchdog restarts the poll loop if it ever goes stale, so
	// the bot can never silently stop answering users.
	if tok := strings.TrimSpace(osGetenv("INSTALL_BOT_TOKEN")); tok != "" {
		go installBotLoop(tok)
		go ibotWatchdog(tok)
	}

	// v3.3: pre-warm the CDN edge list in the background so the first
	// scanner click in the panel is instant instead of a ~20s cold scan.
	// v3.24 bugfix: the fallback used a dead hardcoded dev domain (rotated
	// away in v3.23) — now: no DOMAIN, no pre-warm.
	go func() {
		time.Sleep(15 * time.Second)
		dom := strings.TrimSpace(osGetenv("DOMAIN"))
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

	bootReport()

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
