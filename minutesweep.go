package main

// ─────────── v3.23: تازه‌سازی دقیقه‌ای / minute sweep ───────────
//
// The user's contract (2026-10-26):
//   «کانفیگ‌ها هر دقیقه آپدیت شوند و تازه بشن تا مشکل منفی یک حل شود؛
//    کانفیگ‌هایی که منفی یک می‌دهند حذف شوند؛ کانفیگ‌هایی با پینگ بالای ۱۸۰
//    هم حذف و تازه‌سازی شوند و پینگ پایین‌تر بدهند؛ روی همه اپراتورها
//    (همراه اول / ایرانسل / ADSL / …) به بهینه‌ترین شکل کار کنند.»
//
// Server-side reality of that contract:
//   * FRESHNESS — every /sub fetch already rebuilds the links with NEW random
//     SNI subdomains (linkSNI), so the subscription content is different on
//     every fetch. What could go STALE was the edge pool + primary address:
//     the full scanner runs on an hourly cadence (check-host rate limits make
//     a per-minute FULL scan impossible). This sweep is the per-minute layer.
//   * -1 REMOVAL — an edge that cannot complete a TLS handshake (the exact
//     operation behind a -1) is dropped from the pool within one cycle.
//   * PING GATE — an edge whose handshake exceeds SWEEP_PING_MS (default
//     180ms, panel vantage ≈ 2×RTT to the PoP) is pruned and replaced.
//   * ALL OPERATORS — the subscription keeps carrying the whole pool (region
//     order preserved), the DNS-auto row, the ORIGIN family and 🎭 fronts, so
//     every operator keeps picking its own best route.
//
// Cost model: one TLS handshake per edge (≤12) + up to 6 promotion probes,
// bounded by a 4s dial timeout each, concurrency-capped — a couple of seconds
// per minute, no external probe APIs (check-host stays on the hourly cadence).

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

const (
	sweepMinEdges   = 3  // below this, promote fresh candidates into the pool
	sweepMaxEdges   = 12 // pool cap (buildLinks still ships the top 5 rows)
	sweepPromoteTry = 6  // max candidate probes per sweep cycle
)

// sweepRunning keeps the sweep and the full scan from fighting over
// state.TopEdges (the scan wins; the sweep retries next minute).
var sweepRunning atomic.Bool

// sweepDoctor re-verifies the transports after a primary-address change. A
// var so tests can silence the background launch (the test harness swaps the
// global state pointer without locks — production never does that).
var sweepDoctor = func() { go doctorRun() }

// sweepRescan asks the full scanner for a fresh opinion when the sweep empties
// the whole pool (same testability reason).
var sweepRescan = func() { go safeAutoScan() }

// sweepProbe measures one edge: handshake milliseconds + alive flag. A var so
// tests can stub the network away (same pattern as irProbeTLS).
var sweepProbe = func(ip, domain string) (float64, bool) {
	r := measureEdgeSpeed(ip, domain, 8, 4*time.Second)
	return r.HsMs, r.OK
}

// sweepCandidates is the promotion source (var for the same testability
// reason): the geo-balanced, TLS-verified bunny edge shortlist.
var sweepCandidates = func(domain string) ([]string, map[string]map[string]string) {
	e, geo, _ := bunnyEdgesFor(domain, "4")
	return e, geo
}

// sweepEvery is the cadence (env SWEEP_SECONDS, default 60, clamped 30..3600).
func sweepEvery() time.Duration {
	s := envInt("SWEEP_SECONDS", 60)
	if s < 30 {
		s = 30
	}
	if s > 3600 {
		s = 3600
	}
	return time.Duration(s) * time.Second
}

// sweepPingMs is the prune threshold (env SWEEP_PING_MS overrides state).
func sweepPingMs() int {
	if v := envInt("SWEEP_PING_MS", 0); v > 0 {
		return v
	}
	stateMu.RLock()
	v := state.SweepPingMs
	stateMu.RUnlock()
	if v < 50 || v > 2000 {
		v = 180
	}
	return v
}

func sweepEnabled() bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.SweepOn
}

// sweepOutcome is one cycle's report (for logs, state counters and tests).
type sweepOutcome struct {
	checked  int
	bestMs   float64
	dead     []string
	slow     []string
	promoted []string
	addrOld  string
	addrNew  string
}

func (o *sweepOutcome) changed() bool {
	return o != nil && (len(o.dead) > 0 || len(o.slow) > 0 || len(o.promoted) > 0 || o.addrNew != "")
}

// sweepOnce runs one health pass over the edge pool + auto primary address.
// Order-of-appearance (region order) is PRESERVED among survivors — the v3.3
// lesson: ranking by raw ping would hand the pool to German PoPs that are
// useless for Iranian users; the sweep only REMOVES, it never re-ranks.
func sweepOnce() *sweepOutcome {
	domain := autoScanDomain()
	if domain == "" {
		return nil
	}
	if autoScanRunning.Load() {
		return nil // a full scan owns the pool right now
	}
	if !sweepRunning.CompareAndSwap(false, true) {
		return nil
	}
	defer sweepRunning.Store(false)

	stateMu.RLock()
	var edges []*EdgeScore
	for _, e := range state.TopEdges { // deep copy: probes run unlocked
		cp := *e
		edges = append(edges, &cp)
	}
	addr := strings.TrimSpace(state.Address)
	autoAddr := state.AutoAddr
	stateMu.RUnlock()
	if len(edges) == 0 {
		return nil
	}

	threshold := float64(sweepPingMs())
	o := &sweepOutcome{}
	var kept []*EdgeScore
	bad := map[string]bool{}
	for _, e := range edges {
		o.checked++
		ms, ok := sweepProbe(e.IP, domain)
		if !ok {
			o.dead = append(o.dead, e.IP)
			bad[e.IP] = true
			continue
		}
		if ms > threshold {
			o.slow = append(o.slow, fmt.Sprintf("%s·%.0fms", e.IP, ms))
			bad[e.IP] = true
			continue
		}
		e.Med = ms
		e.TS = time.Now().Unix()
		if o.bestMs == 0 || ms < o.bestMs {
			o.bestMs = ms
		}
		kept = append(kept, e)
	}

	// Promotion: the pool must never fall below sweepMinEdges alive edges —
	// a subscription with one route is one ISP block away from -1 everywhere.
	if len(kept) < sweepMinEdges {
		cur := map[string]bool{}
		for _, e := range edges {
			cur[e.IP] = true
		}
		cand, geo := sweepCandidates(domain)
		tried := 0
		for _, ip := range cand {
			if tried >= sweepPromoteTry || len(kept) >= sweepMaxEdges {
				break
			}
			if cur[ip] || edgeBlockedState(ip) {
				continue
			}
			tried++
			ms, ok := sweepProbe(ip, domain)
			if !ok || ms > threshold {
				continue
			}
			e := &EdgeScore{IP: ip, TS: time.Now().Unix(), Med: ms}
			if g := geo[ip]; g != nil {
				e.CC = g["cc"]
				e.City = g["city"]
			}
			kept = append(kept, e)
			cur[ip] = true
			o.promoted = append(o.promoted, fmt.Sprintf("%s·%.0fms", ip, ms))
		}
	}

	// Auto primary: when the auto-applied address just measured dead/slow, the
	// first surviving edge (region order) takes over. A MANUAL address is the
	// admin's ground truth — never rewritten here (buildLinks already demotes
	// it at request time while it measures dead).
	if autoAddr && bad[addr] && len(kept) > 0 && kept[0].IP != addr {
		o.addrOld, o.addrNew = addr, kept[0].IP
	}

	stateMu.Lock()
	state.TopEdges = kept
	state.SweepAt = time.Now().Unix()
	state.SweepChecked += o.checked
	state.SweepDropped += len(o.dead) + len(o.slow)
	state.SweepPromoted += len(o.promoted)
	if o.addrNew != "" {
		state.Address = o.addrNew
		state.AutoAddr = true
	}
	saveStateLocked()
	stateMu.Unlock()

	if o.changed() {
		logf("minute-sweep: %d/%d ok (best %.0fms) — dead %v · slow>%dms %v · promoted %v",
			o.keptCount(), o.checked, o.bestMs, o.dead, sweepPingMs(), o.slow, o.promoted)
		if o.addrNew != "" {
			logf("minute-sweep: auto address %s → %s", o.addrOld, o.addrNew)
			sweepDoctor() // the transports ride the primary — re-verify it
		}
	}
	// Pool empty even after promotion: the CDN itself is unreachable from the
	// panel — ask the full scanner (IR gates included) for a fresh opinion.
	if len(kept) == 0 && time.Since(time.Unix(autoScanLastAt(), 0)) > 5*time.Minute {
		sweepRescan()
	}
	return o
}

func (o *sweepOutcome) keptCount() int {
	if o == nil {
		return 0
	}
	return o.checked - len(o.dead) - len(o.slow)
}

// sweepSummary is the compact status block embedded in autoScanSummary →
// statePayload (the panel's scanner card + status API).
func sweepSummary() map[string]any {
	stateMu.RLock()
	on := state.SweepOn
	at := state.SweepAt
	pm := state.SweepPingMs
	checked := state.SweepChecked
	dropped := state.SweepDropped
	promoted := state.SweepPromoted
	pool := len(state.TopEdges)
	stateMu.RUnlock()
	if pm < 50 || pm > 2000 {
		pm = 180
	}
	return map[string]any{
		"on":       on,
		"every_s":  int(sweepEvery().Seconds()),
		"ping_ms":  sweepPingMs(),
		"at":       at,
		"checked":  checked,
		"dropped":  dropped,
		"promoted": promoted,
		"pool":     pool,
		"cfg_ping": pm,
	}
}

// sweepLoop runs the sweep forever (first pass 75s after boot — the full scan
// starts at 90s and typically populates the pool first).
// v3.21 convention: recover inside the loop so one bad cycle can never kill
// the ticker goroutine.
func sweepLoop() {
	go func() {
		time.Sleep(75 * time.Second)
		t := time.NewTicker(sweepEvery())
		defer t.Stop()
		for range t.C {
			if !sweepEnabled() {
				continue
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						logf("minute-sweep panic recovered: %v", r)
					}
				}()
				sweepOnce()
			}()
		}
	}()
}
