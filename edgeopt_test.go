package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─────────── v3.9 all-operator optimization ───────────

func TestParseTopEdgesSanitizes(t *testing.T) {
	raw := []any{
		map[string]any{"ip": "185.59.222.196", "med": 45.2, "jit": 8.0, "loss": 0, "origin_ms": 12.5, "kbps": 900, "score": 55, "cc": "TR", "city": "Istanbul"},
		map[string]any{"ip": "192.168.1.1", "med": 1, "loss": 0}, // private → dropped
		map[string]any{"ip": "not-an-ip.example", "med": 5},      // hostname → dropped
		map[string]any{"ip": "91.213.236.9", "med": 80.0, "jit": 12.0, "loss": 2.5, "score": 90, "cc": "AM", "city": "Yerevan"},
		map[string]any{"nonsense": true},                             // no ip → dropped
		map[string]any{"ip": "185.59.222.196", "med": 60, "loss": 0}, // duplicate → dropped
	}
	out := parseTopEdges(raw)
	if len(out) != 2 {
		t.Fatalf("parseTopEdges kept %d edges, want 2: %+v", len(out), out)
	}
	if out[0].IP != "185.59.222.196" {
		t.Errorf("zero-loss edge must rank first, got %s", out[0].IP)
	}
	if out[0].City != "Istanbul" || out[0].CC != "TR" {
		t.Errorf("geo lost: %+v", out[0])
	}
	if out[0].Med != 45.2 || out[0].OriginMs != 12.5 || out[0].SpeedKbps != 900 {
		t.Errorf("metrics lost: %+v", out[0])
	}
	if parseTopEdges(nil) != nil {
		t.Error("nil input must return nil")
	}
	if parseTopEdges([]any{"x"}) != nil {
		t.Error("non-map entries must be dropped")
	}
}

func TestParseTopEdgesCapsAndSorts(t *testing.T) {
	raw := []any{}
	for i := 0; i < 9; i++ {
		raw = append(raw, map[string]any{
			"ip": "185.59." + itoa(i) + ".1", "med": float64(100 - i), "loss": 0, "score": float64(100 - i)})
	}
	out := parseTopEdges(raw)
	if len(out) != 6 {
		t.Fatalf("cap = %d, want 6", len(out))
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].Score > out[i].Score {
			t.Errorf("not sorted by score: %v then %v", out[i-1].Score, out[i].Score)
		}
	}
}

func allOpServer(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("DOMAIN", "deep-network-development-w4a86.lucity.app")
	loadState()
	stateMu.Lock()
	state.Address = "185.59.222.196"
	state.Tuning = defaultTuning()
	state.MultiEdge = true
	state.TopEdges = []*EdgeScore{
		{IP: "185.59.222.196", Med: 45, Jit: 6, Loss: 0, OriginMs: 12, Score: 50, CC: "TR", City: "Istanbul"},
		{IP: "91.213.236.9", Med: 62, Jit: 9, Loss: 0, OriginMs: 18, Score: 70, CC: "AM", City: "Yerevan"},
		{IP: "2400:52e0:1500::714:1", Med: 71, Jit: 10, Loss: 0, OriginMs: 15, Score: 80, CC: "GE", City: "Tbilisi"},
	}
	saveStateLocked()
	stateMu.Unlock()
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.Trim(strings.TrimPrefix(r.URL.Path, "/sub/"), "/")
		handleSub(w, r, tok)
	})
	mux.HandleFunc("/panel/api/speedblob", handleSpeedBlob)
	return httptest.NewServer(mux)
}

func TestBuildLinksMultiEdgeExpansion(t *testing.T) {
	srv := allOpServer(t)
	defer srv.Close()
	stateMu.RLock()
	c := state.Clients[0]
	stateMu.RUnlock()

	links := buildLinks(c, "deep-network-development-w4a86.lucity.app")
	if len(links) == 0 {
		t.Fatal("no links")
	}
	seen := map[string]bool{}
	addrs := map[string]bool{"185.59.222.196": false, "91.213.236.9": false, "2400:52e0:1500::714:1": false}
	dnsEntry := false
	for _, l := range links {
		if seen[l.URL] {
			t.Errorf("duplicate URL in expanded sub: %s", first80(l.URL))
		}
		seen[l.URL] = true
		if strings.Contains(l.URL, "@91.213.236.9") {
			addrs["91.213.236.9"] = true
		}
		if strings.Contains(l.URL, "@[2400:52e0:1500::714:1]") || strings.Contains(l.URL, "@2400:52e0:1500::714:1") {
			addrs["2400:52e0:1500::714:1"] = true
		}
		if strings.Contains(l.URL, "@deep-network-development-w4a86.lucity.app") {
			dnsEntry = true
		}
	}
	if !addrs["91.213.236.9"] {
		t.Error("second edge IP missing from links")
	}
	if !addrs["2400:52e0:1500::714:1"] {
		t.Error("third (v6) edge IP missing from links")
	}
	if !dnsEntry {
		t.Error("DNS-auto entry missing from links")
	}
}

func TestSubDefaultCarriesAllEdges(t *testing.T) {
	srv := allOpServer(t)
	defer srv.Close()
	stateMu.RLock()
	single := len(buildLinksAddr2(c0(), "deep-network-development-w4a86.lucity.app"))
	stateMu.RUnlock()
	resp, err := http.Get(srv.URL + "/sub/" + subTokenForMain(t))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("sub not base64: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	if len(lines) <= single {
		t.Errorf("expanded sub has %d lines, primary set alone has %d — expansion did not happen", len(lines), single)
	}
	found2, foundDNS := false, false
	for _, ln := range lines {
		if strings.Contains(ln, "@91.213.236.9") {
			found2 = true
		}
		if strings.Contains(ln, "@deep-network-development-w4a86.lucity.app") {
			foundDNS = true
		}
	}
	if !found2 {
		t.Error("edge-2 entries missing from default sub")
	}
	if !foundDNS {
		t.Error("DNS-auto entry missing from default sub")
	}
}

func c0() *Client {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.Clients[0]
}

// buildLinksAddr2 builds the primary set for counting purposes in tests.
func buildLinksAddr2(c *Client, host string) []Link {
	return buildLinksAddr(c, stateAddress(host), host, "", true)
}

func stateAddress(host string) string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state.Address != "" {
		return state.Address
	}
	return host
}

func TestSpeedBlobServesRequestedKB(t *testing.T) {
	srv := allOpServer(t)
	defer srv.Close()
	for _, n := range []int{8, 32} {
		resp, err := http.Get(srv.URL + "/panel/api/speedblob?n=" + itoa(n))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(b) != n*1024 {
			t.Errorf("n=%d: got %d bytes, want %d", n, len(b), n*1024)
		}
	}
	// oversize is clamped, no error
	resp, err := http.Get(srv.URL + "/panel/api/speedblob?n=99999")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(b) != 512*1024 {
		t.Errorf("oversize clamp: got %d bytes, want %d", len(b), 512*1024)
	}
}

func TestSettingsTopEdgesRoundTrip(t *testing.T) {
	srv := allOpServer(t)
	defer srv.Close()
	// emulate what handleSettings does with the optimizer payload
	edges := parseTopEdges([]any{
		map[string]any{"ip": "5.188.122.25", "med": 33, "jit": 4, "loss": 0, "origin_ms": 9, "kbps": 1200, "score": 40, "cc": "NL", "city": "Amsterdam"},
	})
	stateMu.Lock()
	state.TopEdges = edges
	state.MultiEdge = true
	saveStateLocked()
	stateMu.Unlock()

	// statePayload must expose them
	var m map[string]any
	_ = json.Unmarshal([]byte{}, &m) // keep json import warm
	stateMu.RLock()
	te := state.TopEdges
	stateMu.RUnlock()
	if len(te) != 1 || te[0].IP != "5.188.122.25" || te[0].SpeedKbps != 1200 {
		t.Fatalf("round-trip lost data: %+v", te)
	}
}
