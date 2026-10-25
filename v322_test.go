package main

// ─────────── v3.21.2 tests: XHTTP direct-to-origin + completion-based doctor ───────────
// The 2026-10-25 incident: every XHTTP link routed through a bunny edge
// stalled at 95-97% of any chunked download and never completed — bunny's h2
// layer holds the tail of long GET streams. v2rayNG's tiny ping passed, so
// the sub looked alive while every page hung ("configs ping but nothing
// loads"). v3.21.2 moves XHTTP to the ORIGIN ingress (never bunny), demotes
// it to the last row, and upgrades the doctor from a HEAD /generate_204
// handshake check to a real CHUNKED full-body completion probe.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// injectOrigin pre-seeds the origin cache so link/doctor emission is
// deterministic offline (no DNS, no ip-api).
func injectOrigin(t *testing.T, host, ip, city, cc string) {
	t.Helper()
	originMu.Lock()
	originCache[strings.ToLower(strings.TrimSpace(host))] = originEntry{
		ip: ip, city: city, cc: cc, at: time.Now(),
	}
	originMu.Unlock()
}

// The full sub order after v3.21.2: per address group WS → HU → VMess →
// Trojan, one direct XHTTP row (primary only, last), then the 🎭 front
// groups WITHOUT XHTTP (their old xhttp rows went through bunny and would
// hang), then the 🛡️ direct row.
func TestSubOrderAndXHTTPExclusivity(t *testing.T) {
	v320Setup(t)
	injectOrigin(t, "deep-network-development-w4a86.lucity.app", "84.17.37.214", "Frankfurt", "DE")
	stateMu.Lock()
	state.MultiEdge = true
	state.TopEdges = []*EdgeScore{
		{IP: "143.244.45.177", Med: 73, Loss: 0, City: "Frankfurt", CC: "DE", IRTLS: 1, IRTLSAt: 1792861085},
	}
	stateMu.Unlock()
	links := buildLinks(lmTestClient(), "deep-network-development-w4a86.lucity.app")
	if len(links) < 10 {
		t.Fatalf("expected a full sub, got %d links", len(links))
	}
	sawX, frontX := 0, 0
	for i, l := range links {
		if strings.Contains(l.URL, "type=xhttp") {
			sawX++
			if !strings.Contains(l.URL, "@84.17.37.214:443") {
				t.Errorf("xhttp row %d must dial the origin IP: %s", i, first80(l.URL))
			}
		}
		// no XHTTP row may ride a bunny edge or a 🎭 front anymore
		if strings.Contains(l.URL, "type=xhttp") &&
			(strings.Contains(l.URL, "@138.199.37.231") || strings.Contains(l.URL, "@143.244.45.177")) {
			t.Errorf("xhttp row %d must not route through an edge: %s", i, first80(l.URL))
		}
		if strings.Contains(l.URL, "type=xhttp") && strings.Contains(linkDisplayName(l), "🎭") {
			frontX++
		}
	}
	if sawX != 1 {
		t.Errorf("want exactly one XHTTP row (primary, direct), saw %d", sawX)
	}
	if frontX != 0 {
		t.Errorf("🎭 front groups must not carry XHTTP rows, saw %d", frontX)
	}
	// primary group head: WS, HU, VMess, Trojan before the direct XHTTP
	var keys []string
	for _, l := range links {
		keys = append(keys, l.Key)
	}
	firstFive := strings.Join(keys[:5], ",")
	if !strings.HasPrefix(firstFive, "vless-ws,vless-hu,vmess-ws,trojan-ws") {
		t.Errorf("primary group order = %s, want vless-ws,vless-hu,vmess-ws,trojan-ws first", firstFive)
	}
}

// The doctor's xhttp config must dial the origin with the domain SNI, and
// the address must be the origin IP — never the bunny edge.
func TestDoctorXHTTPDirect(t *testing.T) {
	v320Setup(t)
	domain := "deep-network-development-w4a86.lucity.app"
	injectOrigin(t, domain, "84.17.37.214", "Frankfurt", "DE")
	cfg, err := doctorClientConfig(lmTestClient(), "vless-xhttp", "138.199.37.231", domain, 27124)
	if err != nil {
		t.Fatalf("doctorClientConfig: %v", err)
	}
	obs, _ := cfg["outbounds"].([]map[string]any)
	if len(obs) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(obs))
	}
	vs, _ := obs[0]["settings"].(map[string]any)
	vn, _ := vs["vnext"].([]map[string]any)
	if len(vn) != 1 || vn[0]["address"] != "84.17.37.214" {
		t.Fatalf("xhttp must dial the origin IP, got %+v", vn)
	}
	st, _ := obs[0]["streamSettings"].(map[string]any)
	tl, _ := st["tlsSettings"].(map[string]any)
	if tl["serverName"] != domain {
		t.Errorf("xhttp SNI = %v, want the panel domain", tl["serverName"])
	}
	xs, _ := st["xhttpSettings"].(map[string]any)
	if xs["host"] != domain {
		t.Errorf("xhttp host header = %v, want the panel domain", xs["host"])
	}
	if xs["mode"] != "packet-up" {
		t.Errorf("xhttp mode = %v, want packet-up", xs["mode"])
	}
}

// speedblob chunked=1: no Content-Length, Transfer-Encoding chunked, full
// N-KB body — the completion target the doctor relies on. The plain path
// keeps its Content-Length (edge speed tests depend on it).
func TestSpeedBlobChunked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleSpeedBlob(w, r)
	}))
	defer srv.Close()

	// plain path: CL present
	resp, err := srv.Client().Get(srv.URL + "/panel/api/speedblob?n=32")
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != int64(32*1024) {
		t.Errorf("plain speedblob CL = %d, want %d", resp.ContentLength, 32*1024)
	}
	resp.Body.Close()

	// chunked path: no CL
	resp2, err := srv.Client().Get(srv.URL + "/panel/api/speedblob?n=96&chunked=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.ContentLength != -1 {
		t.Errorf("chunked speedblob must not declare Content-Length, got %d", resp2.ContentLength)
	}
	if len(resp2.TransferEncoding) == 0 || resp2.TransferEncoding[0] != "chunked" {
		t.Errorf("chunked speedblob TE = %v, want chunked", resp2.TransferEncoding)
	}
	buf := make([]byte, 32*1024)
	total := 0
	for {
		n, err := resp2.Body.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if total < 96*1024 {
		t.Errorf("chunked speedblob body = %d, want >= %d", total, 96*1024)
	}
}

// originFor must refuse non-domains and localhost (no origin row can be
// emitted for an IP-addressed or local deployment), and cache its result.
func TestOriginForGuards(t *testing.T) {
	if o := originFor(""); o.ip != "" {
		t.Errorf("empty host must not resolve, got %+v", o)
	}
	if o := originFor("138.199.37.231"); o.ip != "" {
		t.Errorf("IP literal must not resolve, got %+v", o)
	}
	if o := originFor("localhost"); o.ip != "" {
		t.Errorf("localhost must not resolve, got %+v", o)
	}
	if o := originFor("foo.localhost"); o.ip != "" {
		t.Errorf("*.localhost must not resolve, got %+v", o)
	}
}
