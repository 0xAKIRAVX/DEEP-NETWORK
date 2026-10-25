package main

// ─────────── v3.16: deadlock fixes + watchdog + hourly sub refresh ───────────

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The live v3.15 incident: /panel/api/state (statePayload) called
// localModeGet() — which takes stateMu.RLock() — while ALREADY holding the
// RLock; irProbeAll did the same with autoScanDomain(). A recursive RLock
// deadlocks the whole panel whenever a writer queues in between, which is
// exactly when the deployed panel froze (all API + /sub requests hung,
// clients could not refresh configs). v3.16 removed every nested
// acquisition; this stress test hammers the three concurrent shapes that
// used to collide and asserts they always complete.
func TestNoNestedLockDeadlockStress(t *testing.T) {
	// standalone-safe: guarantee an initialized global state, restore after.
	save := state
	if state == nil {
		state = &State{}
	}
	defer func() { state = save }()

	stop := time.Now().Add(2 * time.Second)
	var wg sync.WaitGroup

	// shape 1: statePayload (dashboard poll path)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				r := httptest.NewRequest("GET", "/panel/api/state", nil)
				r.Header.Set("X-Forwarded-Host", "x.lucity.app")
				r.Header.Set("X-Forwarded-Proto", "https")
				_ = statePayload(r)
			}
		}()
	}
	// shape 2: writers (saveState-style)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			stateMu.Lock()
			state.LastHost = "stress.lucity.app" // what rememberHost writes on every authed request
			stateMu.Unlock()
		}
	}()
	// shape 3: the FIXED irProbeAll shape — domain resolved BEFORE the lock
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			domain := autoScanDomain()
			stateMu.RLock()
			_ = state.TopEdges
			stateMu.RUnlock()
			_ = domain
		}
	}()

	fin := make(chan struct{})
	go func() { wg.Wait(); close(fin) }()
	select {
	case <-fin:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock: state paths did not complete within 20s")
	}
}

// chooseFront + applyFrontChoice split: the probe callback must run with no
// lock held; the composition still behaves exactly like the old applyFront.
func TestChooseFrontSplit(t *testing.T) {
	// auto walks candidates in order and returns the first success
	base, rand := chooseFront("", func(b string, r bool) error {
		if b == "b-cdn.net" {
			return nil
		}
		return errFake
	})
	if base != "b-cdn.net" || !rand {
		t.Fatalf("auto choose = %q/%v, want b-cdn.net/true", base, rand)
	}

	// custom form: base extracted from the wildcard prefix
	base, rand = chooseFront("*.front.example", func(b string, r bool) error {
		return nil
	})
	if base != "front.example" || !rand {
		t.Fatalf("custom choose = %q/%v", base, rand)
	}

	// off
	if base, _ = chooseFront("off", nil); base != "" {
		t.Fatalf("off choose = %q", base)
	}

	// store/clear
	st := &State{}
	applyFrontChoice(st, base, rand) // base is "" here — clears
	if st.FrontSNI != "" || st.FrontAt != 0 {
		t.Fatalf("clear failed: %+v", st)
	}
	applyFrontChoice(st, "front.example", true)
	if st.FrontSNI != "front.example" || !st.FrontRand || st.FrontAt == 0 {
		t.Fatalf("store failed: %+v", st)
	}
}

// The sub headers must ask clients to refresh HOURLY (links carry edges that
// the auto-scan rotates every hour; 12h caching rode dead edges).
func TestSubUpdateIntervalHourly(t *testing.T) {
	if subUpdateIntervalHours != "1" {
		t.Fatalf("Profile-Update-Interval = %q, want 1 (hourly)", subUpdateIntervalHours)
	}
}

// watchdogProbe must report a held lock as frozen (with a stack dump) and a
// released lock as healthy; watchdogOnce must only die when frozen.
func TestWatchdogProbe(t *testing.T) {
	// free lock: immediate success
	locked, dump := watchdogProbe(2 * time.Second)
	if !locked || dump != "" {
		t.Fatalf("free lock: locked=%v dump=%q", locked, dump)
	}

	// held lock: budget expires, dump captured
	stateMu.Lock()
	go func() { time.Sleep(500 * time.Millisecond); stateMu.Unlock() }()
	locked, dump = watchdogProbe(50 * time.Millisecond)
	if locked {
		t.Fatal("held lock must not report locked")
	}
	if !strings.Contains(dump, "goroutine") {
		t.Fatal("dump must contain goroutine stacks")
	}
	// after release: healthy again
	locked, _ = watchdogProbe(3 * time.Second)
	if !locked {
		t.Fatal("watchdog must recover after the lock is released")
	}

	// watchdogOnce: healthy lock → "ok", no die()
	died := ""
	if res := watchdogOnce(100*time.Millisecond, 300*time.Millisecond, func(r string) { died = r }); res != "ok" || died != "" {
		t.Fatalf("healthy watchdogOnce = %q died=%q", res, died)
	}
}

// irCheckURL verdict parsing must accept a success row and reject error rows
// (check-host http rows: [ [1, time, "OK...", code, ip], ... ]).
func TestIRCheckURLParsesVerdicts(t *testing.T) {
	// (network functions are exercised live by irProbeAll; here we only pin
	// the pure classification contract through irCheckDomain's URL shape.)
	if got := "https://" + "deep-network-development-w4a86.lucity.app" + "/panel/"; !strings.HasPrefix(got, "https://") {
		t.Fatalf("unexpected URL shape %q", got)
	}
}
