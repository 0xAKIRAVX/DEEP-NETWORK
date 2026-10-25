package main

// ─────────── v3.22 tests: PRIMARY IR gate + the ORIGIN family ───────────
// The 2026-10-25 block wave: the Frankfurt primary (state.Address) measured
// TLS-dead from every Iranian node while Kyiv lived — 16 of 22 sub rows rode
// it (primary group + every 🎭 front + 🛡️) and every one read -1 in v2rayNG,
// with NO gate in place to notice. v3.22 gates the primary exactly like the
// edges (demote at build time, never rewrite the admin's setting) and adds
// the ORIGIN family (bunnyinfra hosting range — different IP family from
// every bunny CDN edge, gated on DomainIR==1).

import (
	"strings"
	"testing"
	"time"
)

const v322Domain = "deep-network-development-w4a86.lucity.app"

// A TLS-dead primary must not ride ANY row: the primary group, the 🎭 front
// variants and 🛡️ all demote to the best IR-alive edge; state.Address keeps
// its value for when the wave lifts.
func TestPrimaryDemotesWhenIRDead(t *testing.T) {
	v320Setup(t)
	stateMu.Lock()
	state.PrimaryIR = 2
	state.PrimaryIRAt = time.Now().Unix()
	state.MultiEdge = true
	state.DomainIR = 2 // origin family hidden — isolate the primary gate
	state.TopEdges = []*EdgeScore{
		{IP: "143.244.45.177", Med: 73, Loss: 0, City: "Kyiv", CC: "UA", IRTLS: 1, IRTLSAt: time.Now().Unix()},
	}
	stateMu.Unlock()
	links := buildLinks(lmTestClient(), v322Domain)
	if len(links) == 0 {
		t.Fatal("no links built")
	}
	for _, l := range links {
		if strings.Contains(l.URL, "@138.199.37.231") {
			t.Errorf("dead primary must not ride any row: %s", first80(l.URL))
		}
	}
	if !strings.Contains(links[0].URL, "@143.244.45.177:443") {
		t.Errorf("first row must ride the demoted (Kyiv) primary: %s", first80(links[0].URL))
	}
}

// Alive (1) and unmeasured (0) primaries keep riding — the gate only acts on
// a MEASURED-dead verdict, so an unreachable probe can never silently
// re-route the subscription.
func TestPrimaryKeptWhenAliveOrUnknown(t *testing.T) {
	v320Setup(t)
	stateMu.Lock()
	state.DomainIR = 2
	stateMu.Unlock()
	for _, ir := range []int{0, 1} {
		stateMu.Lock()
		state.PrimaryIR = ir
		stateMu.Unlock()
		links := buildLinks(lmTestClient(), v322Domain)
		saw := false
		for _, l := range links {
			if strings.Contains(l.URL, "@138.199.37.231") {
				saw = true
			}
		}
		if !saw {
			t.Errorf("PrimaryIR=%d: alive/unknown primary must keep riding", ir)
		}
	}
}

// The ORIGIN family: full transport set on the origin ingress IP with the
// panel domain as SNI, gated on DomainIR==1; XHTTP rides ONLY here.
func TestOriginGroupGatedOnDomainIR(t *testing.T) {
	v320Setup(t)
	injectOrigin(t, v322Domain, "84.17.37.214", "Frankfurt", "DE")

	// alive → group rides, exactly one XHTTP, domain SNI everywhere
	stateMu.Lock()
	state.DomainIR = 1
	stateMu.Unlock()
	links := buildLinks(lmTestClient(), v322Domain)
	xhttp, orgWS := 0, 0
	for _, l := range links {
		u := l.URL
		if strings.Contains(u, "type=xhttp") {
			xhttp++
			if !strings.Contains(u, "@84.17.37.214:443") {
				t.Errorf("origin XHTTP must dial the origin IP: %s", first80(u))
			}
			if !strings.Contains(u, "sni=deep-network") {
				t.Errorf("origin XHTTP must carry the panel-domain SNI: %s", first80(u))
			}
		}
		if strings.Contains(u, "@84.17.37.214:443") && strings.Contains(u, "type=ws") {
			orgWS++
		}
	}
	if xhttp != 1 {
		t.Errorf("want exactly 1 XHTTP row, got %d", xhttp)
	}
	if orgWS == 0 {
		t.Error("origin WS row missing")
	}

	// dead → nothing from the origin family, and NO XHTTP row anywhere
	stateMu.Lock()
	state.DomainIR = 2
	stateMu.Unlock()
	for _, l := range buildLinks(lmTestClient(), v322Domain) {
		if strings.Contains(l.URL, "@84.17.37.214") {
			t.Errorf("origin family must be hidden while DomainIR==2: %s", first80(l.URL))
		}
		if strings.Contains(l.URL, "type=xhttp") {
			t.Errorf("XHTTP must not ride while the origin family is dead: %s", first80(l.URL))
		}
	}
}

// 🛡️ مستقیم must never point at the measured-dead primary either.
func TestLocalDirectSkipsIRDeadPrimary(t *testing.T) {
	v320Setup(t)
	stateMu.Lock()
	state.PrimaryIR = 2
	state.MultiEdge = true
	state.TopEdges = []*EdgeScore{
		{IP: "143.244.45.177", Med: 73, Loss: 0, City: "Kyiv", CC: "UA", IRTLS: 1, IRTLSAt: time.Now().Unix()},
	}
	lm := *state.LocalMode
	stateMu.Unlock()
	if got := localDirectAddr(lm, v322Domain); got != "143.244.45.177" {
		t.Errorf("localDirectAddr = %q, want the Kyiv edge while the primary is IR-dead", got)
	}
}

// The scan cycle stores the normalized primary verdict (1 alive / 2 dead;
// -1 probe-unavailable keeps the previous verdict untouched).
func TestIrProbePrimaryStoresVerdict(t *testing.T) {
	v320Setup(t)
	orig := irProbeTLS
	defer func() { irProbeTLS = orig }()

	irProbeTLS = func(ip string) int { return 0 } // dead
	irProbePrimary()
	stateMu.RLock()
	ir, at := state.PrimaryIR, state.PrimaryIRAt
	stateMu.RUnlock()
	if ir != 2 || at == 0 {
		t.Errorf("dead probe: PrimaryIR=%d at=%d, want 2 + fresh", ir, at)
	}

	irProbeTLS = func(ip string) int { return -1 } // unavailable
	stateMu.Lock()
	state.PrimaryIRAt = 0
	stateMu.Unlock()
	irProbePrimary()
	stateMu.RLock()
	ir, at = state.PrimaryIR, state.PrimaryIRAt
	stateMu.RUnlock()
	if ir != 2 || at != 0 {
		t.Errorf("unavailable probe must keep the previous verdict, got PrimaryIR=%d at=%d", ir, at)
	}
}
