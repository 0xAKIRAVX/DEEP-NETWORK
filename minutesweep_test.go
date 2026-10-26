package main

// ─────────── v3.23 tests: the minute sweep ───────────
// The sweep is the user's "هر دقیقه تازه شود" contract: dead (TLS-fail) and
// slow (> threshold) edges leave the pool within one cycle, promotions refill
// it, and the auto primary address self-heals. All network paths are stubbed.

import (
	"strings"
	"testing"
	"time"
)

func sweepTestState(edges []*EdgeScore, addr string, autoAddr bool) {
	state = &State{
		UUID:        "test-uuid",
		AdminUser:   "admin",
		AdminPass:   "x",
		Address:     addr,
		AutoAddr:    autoAddr,
		TopEdges:    edges,
		MultiEdge:   true,
		SweepOn:     true,
		SweepPingMs: 180,
		AutoScan:    true,
		AutoScanAt:  time.Now().Unix(), // keep the empty-pool rescan path quiet
		CfgFmt:      defaultCfgFmt,
		SNIOverride: "panel.lucity.app", // autoScanDomain() source
		Protocols:   map[string]bool{},
	}
	for _, k := range protoKeys {
		state.Protocols[k] = true
	}
}

func withSweepStubs(t *testing.T, probe func(ip, domain string) (float64, bool), cand []string) (restore func()) {
	t.Helper()
	oldProbe, oldCand, oldDoc, oldRescan := sweepProbe, sweepCandidates, sweepDoctor, sweepRescan
	sweepProbe = probe
	sweepCandidates = func(string) ([]string, map[string]map[string]string) {
		return cand, nil
	}
	sweepDoctor = func() {}
	sweepRescan = func() {}
	return func() { sweepProbe, sweepCandidates, sweepDoctor, sweepRescan = oldProbe, oldCand, oldDoc, oldRescan }
}

func TestSweepPrunesDeadAndSlowKeepsRegionOrder(t *testing.T) {
	restore := withSweepStubs(t, func(ip, domain string) (float64, bool) {
		switch ip {
		case "1.1.1.1":
			return 0, false // dead — TLS handshake fails = the -1 operation
		case "2.2.2.2":
			return 350, true // slow — above the 180ms gate
		case "3.3.3.3":
			return 60, true // good
		case "4.4.4.4":
			return 90, true // good
		}
		return 0, false
	}, nil)
	defer restore()

	sweepTestState([]*EdgeScore{
		{IP: "1.1.1.1", CC: "TR", City: "Istanbul"},
		{IP: "2.2.2.2", CC: "TR", City: "Ankara"},
		{IP: "3.3.3.3", CC: "AZ", City: "Baku"},
		{IP: "4.4.4.4", CC: "IQ", City: "Baghdad"},
	}, "1.1.1.1", true)

	o := sweepOnce()
	if o == nil {
		t.Fatal("sweepOnce returned nil")
	}
	if o.checked != 4 {
		t.Fatalf("checked = %d, want 4", o.checked)
	}
	if len(o.dead) != 1 || o.dead[0] != "1.1.1.1" {
		t.Fatalf("dead = %v, want [1.1.1.1]", o.dead)
	}
	if len(o.slow) != 1 || !strings.HasPrefix(o.slow[0], "2.2.2.2") {
		t.Fatalf("slow = %v, want [2.2.2.2·350ms]", o.slow)
	}
	// region order preserved among survivors: Baku stays ahead of Baghdad
	if len(state.TopEdges) != 2 || state.TopEdges[0].IP != "3.3.3.3" || state.TopEdges[1].IP != "4.4.4.4" {
		t.Fatalf("pool after sweep = %v", ipsOf(state.TopEdges))
	}
	if state.TopEdges[0].Med != 60 {
		t.Fatalf("Med not refreshed: %v", state.TopEdges[0].Med)
	}
	if state.SweepDropped != 2 || state.SweepChecked != 4 {
		t.Fatalf("counters: dropped=%d checked=%d", state.SweepDropped, state.SweepChecked)
	}
}

func TestSweepPromotesWhenPoolShort(t *testing.T) {
	restore := withSweepStubs(t, func(ip, domain string) (float64, bool) {
		if ip == "9.9.9.9" {
			return 0, false // candidate that fails — must NOT enter the pool
		}
		if ip == "8.8.8.8" {
			return 210, true // candidate above the gate — must NOT enter either
		}
		if ip == "7.7.7.7" {
			return 70, true // good candidate — promoted
		}
		return 0, false
	}, []string{"9.9.9.9", "8.8.8.8", "7.7.7.7"})
	defer restore()

	sweepTestState([]*EdgeScore{{IP: "1.1.1.1"}}, "1.1.1.1", false)

	o := sweepOnce()
	if o == nil {
		t.Fatal("sweepOnce returned nil")
	}
	// 1 old edge fails → kept=0 → promotion path fires (pool < sweepMinEdges)
	got := ipsOf(state.TopEdges)
	if len(got) != 1 || got[0] != "7.7.7.7" {
		t.Fatalf("pool after promotion = %v, want [7.7.7.7]", got)
	}
	if len(o.promoted) != 1 || !strings.HasPrefix(o.promoted[0], "7.7.7.7") {
		t.Fatalf("promoted = %v", o.promoted)
	}
	if state.SweepPromoted != 1 {
		t.Fatalf("SweepPromoted = %d", state.SweepPromoted)
	}
}

func TestSweepAutoAddressSelfHeals(t *testing.T) {
	restore := withSweepStubs(t, func(ip, domain string) (float64, bool) {
		if ip == "1.1.1.1" {
			return 0, false // the primary is dead
		}
		return 55, true
	}, nil)
	defer restore()

	sweepTestState([]*EdgeScore{
		{IP: "1.1.1.1", CC: "TR", City: "Istanbul"},
		{IP: "5.5.5.5", CC: "AZ", City: "Baku"},
	}, "1.1.1.1", true)

	o := sweepOnce()
	if o.addrOld != "1.1.1.1" || o.addrNew != "5.5.5.5" {
		t.Fatalf("addr transition = %s → %s, want 1.1.1.1 → 5.5.5.5", o.addrOld, o.addrNew)
	}
	if state.Address != "5.5.5.5" || !state.AutoAddr {
		t.Fatalf("state.Address = %q auto=%v", state.Address, state.AutoAddr)
	}
}

func TestSweepNeverTouchesManualAddress(t *testing.T) {
	restore := withSweepStubs(t, func(ip, domain string) (float64, bool) {
		if ip == "1.1.1.1" {
			return 0, false
		}
		return 55, true
	}, nil)
	defer restore()

	sweepTestState([]*EdgeScore{
		{IP: "1.1.1.1", CC: "TR", City: "Istanbul"},
		{IP: "5.5.5.5", CC: "AZ", City: "Baku"},
	}, "1.1.1.1", false) // manual address

	o := sweepOnce()
	if o.addrNew != "" {
		t.Fatalf("manual address was rewritten: %s → %s", o.addrOld, o.addrNew)
	}
	if state.Address != "1.1.1.1" {
		t.Fatalf("state.Address = %q, want unchanged 1.1.1.1", state.Address)
	}
}

func TestSweepPingMsClampAndDefault(t *testing.T) {
	sweepTestState(nil, "", false)
	if got := sweepPingMs(); got != 180 {
		t.Fatalf("sweepPingMs default = %d, want 180", got)
	}
	state.SweepPingMs = 10
	if got := sweepPingMs(); got != 180 { // <50 clamps back to default
		t.Fatalf("sweepPingMs(10) = %d, want 180", got)
	}
	state.SweepPingMs = 900
	if got := sweepPingMs(); got != 900 {
		t.Fatalf("sweepPingMs(900) = %d, want 900", got)
	}
}

func TestSweepSkipsWhileFullScanRuns(t *testing.T) {
	restore := withSweepStubs(t, func(ip, domain string) (float64, bool) {
		t.Fatal("probe must not run while the full scan owns the pool")
		return 0, false
	}, nil)
	defer restore()

	sweepTestState([]*EdgeScore{{IP: "1.1.1.1"}}, "", false)
	autoScanRunning.Store(true)
	defer autoScanRunning.Store(false)
	if o := sweepOnce(); o != nil {
		t.Fatal("sweep must yield to the full scan")
	}
}

func TestSweepLoadStateDefaults(t *testing.T) {
	// fresh state → sweep ON, threshold 180 (the loadState branch)
	oldState := state
	st := &State{}
	if pm := envInt("SWEEP_PING_MS", 0); pm > 0 {
		st.SweepPingMs = pm
	}
	if st.SweepPingMs < 50 || st.SweepPingMs > 2000 {
		st.SweepPingMs = 180
	}
	if st.SweepPingMs != 180 {
		t.Fatalf("default ping threshold = %d, want 180", st.SweepPingMs)
	}
	state = oldState
}

func ipsOf(edges []*EdgeScore) []string {
	var out []string
	for _, e := range edges {
		out = append(out, e.IP)
	}
	return out
}
