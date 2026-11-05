package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ─────────── helpers for tests ───────────

func testState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)
	return dir
}

func freshLoad(t *testing.T) {
	testState(t)
	os.Remove(statePath())
	state = nil
	loadState()
}

// ─────────── 1) vless link formats (the exact params v2rayNG parses) ───────────

func TestLinkFormatsV326(t *testing.T) {
	freshLoad(t)
	initReality()
	if realityPub == "" {
		t.Fatal("reality public key missing")
	}
	c := &Client{Name: "سارا", ID: "674ffda4-2cdd-4286-bbfa-346108aa4f80"}
	links := buildLinks(c, "16.171.14.5")
	if len(links) != 3 {
		t.Fatalf("want 3 links, got %d", len(links))
	}
	byKey := map[string]Link{}
	for _, l := range links {
		byKey[l.Key] = l
	}

	// Vision: first (fastest), tcp + vision flow + reality
	v := byKey["vision"]
	for _, want := range []string{
		"vless://674ffda4-2cdd-4286-bbfa-346108aa4f80@16.171.14.5:8443?",
		"encryption=none", "flow=xtls-rprx-vision", "security=reality",
		"sni=www.microsoft.com", "fp=chrome", "type=tcp",
	} {
		if !strings.Contains(v.URL, want) {
			t.Errorf("vision link missing %q in %s", want, v.URL)
		}
	}
	if strings.Contains(v.URL, "mux=") {
		t.Error("vision link must not carry mux (max speed)")
	}

	// XHTTP: type=xhttp + path + host
	x := byKey["xhttp"]
	for _, want := range []string{
		"@16.171.14.5:2053?", "type=xhttp", "path=%2Fdn", "host=www.cloudflare.com",
		"sni=www.cloudflare.com", "security=reality", "sid=",
	} {
		if !strings.Contains(x.URL, want) {
			t.Errorf("xhttp link missing %q in %s", want, x.URL)
		}
	}

	// gRPC: type=grpc + serviceName + mode=gun
	g := byKey["grpc"]
	for _, want := range []string{
		"@16.171.14.5:2087?", "type=grpc", "serviceName=dn", "mode=gun",
		"sni=www.bing.com", "security=reality",
	} {
		if !strings.Contains(g.URL, want) {
			t.Errorf("grpc link missing %q in %s", want, g.URL)
		}
	}
}

// ─────────── 2) sub token stability (upgrade keeps old sub URLs alive) ───────────

func TestSubTokenStableV326(t *testing.T) {
	freshLoad(t)
	tok := subToken("674ffda4-2cdd-4286-bbfa-346108aa4f80")
	if len(tok) != 32 {
		t.Fatalf("token length %d", len(tok))
	}
	if subToken("674ffda4-2cdd-4286-bbfa-346108aa4f80") != tok {
		t.Error("token not deterministic")
	}
	if subToken("other") == tok {
		t.Error("token collision")
	}
}

// ─────────── 3) v3.2x state migration ───────────

func TestMigrateV325State(t *testing.T) {
	testState(t)
	legacy := map[string]any{
		"uuid":          "674ffda4-2cdd-4286-bbfa-346108aa4f80",
		"admin_user":    "admin",
		"admin_pass":    "oldpass",
		"session_hours": 12,
		"reality_sni":   "www.microsoft.com",
		"clients": []map[string]any{
			{"name": "main", "id": "674ffda4-2cdd-4286-bbfa-346108aa4f80"},
			{"name": "ali", "id": "11111111-2222-3333-4444-555555555555", "up": 1000, "down": 2000},
		},
	}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(statePath(), b, 0o600); err != nil {
		t.Fatal(err)
	}
	state = nil
	loadState()

	// clients carried
	stateMu.RLock()
	defer stateMu.RUnlock()
	if len(state.Clients) != 2 {
		t.Fatalf("want 2 clients after migration, got %d", len(state.Clients))
	}
	if state.UUID != "674ffda4-2cdd-4286-bbfa-346108aa4f80" {
		t.Error("uuid not carried")
	}
	// wizard state: unclaimed (old admin pass NOT carried)
	if state.Profile != nil {
		t.Error("profile must start unclaimed (wizard)")
	}
	if state.AdminUser != "" || state.AdminPass != "" {
		t.Error("legacy admin must not survive migration")
	}
	if state.Migrated != "v3.2x" {
		t.Error("migration marker missing")
	}
	// backup file written
	if _, err := os.Stat(statePath() + ".v325bak"); err != nil {
		t.Error("v3.25 backup not written")
	}
}

// ─────────── 4) setup wizard claim flow ───────────

func TestSetupClaimFlow(t *testing.T) {
	freshLoad(t)

	// claim
	body := `{"first":"علی","last":"رضایی","user":"ali","pass":"pass12345","avatar":""}`
	req := httptest.NewRequest("POST", "/panel/api/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handleSetup(rec, req)
	if rec.Code != 200 {
		t.Fatalf("setup claim status %d: %s", rec.Code, rec.Body.String())
	}
	if !profileClaimed() {
		t.Fatal("profile not claimed after setup")
	}
	stateMu.RLock()
	prof := state.Profile
	stateMu.RUnlock()
	if prof.User != "ali" || prof.First != "علی" || prof.Last != "رضایی" {
		t.Errorf("profile fields wrong: %+v", prof)
	}
	if hashPass("pass12345", prof.PassSalt) != prof.PassHash {
		t.Error("password hash mismatch")
	}

	// second claim must fail (one-shot)
	req2 := httptest.NewRequest("POST", "/panel/api/setup", strings.NewReader(body))
	rec2 := httptest.NewRecorder()
	handleSetup(rec2, req2)
	if rec2.Code != 409 {
		t.Errorf("second claim must 409, got %d", rec2.Code)
	}

	// login with the claimed password
	lb := `{"user":"ali","pass":"pass12345"}`
	lreq := httptest.NewRequest("POST", "/panel/api/login", strings.NewReader(lb))
	lrec := httptest.NewRecorder()
	handleLogin(lrec, lreq)
	if lrec.Code != 200 {
		t.Errorf("login after claim failed: %d %s", lrec.Code, lrec.Body.String())
	}
	// wrong pass rejected
	wb := `{"user":"ali","pass":"WRONG"}`
	wreq := httptest.NewRequest("POST", "/panel/api/login", strings.NewReader(wb))
	wrec := httptest.NewRecorder()
	handleLogin(wrec, wreq)
	if wrec.Code != 401 {
		t.Errorf("wrong pass must 401, got %d", wrec.Code)
	}
}

// ─────────── 5) port fallback ladder ───────────

func TestPickPortFallback(t *testing.T) {
	taken := map[int]bool{80: true, apiPort: true}
	// preferred free → returns it
	if p := pickPort(8443, taken); p != 8443 {
		t.Errorf("want 8443, got %d", p)
	}
	// preferred taken → first free ladder port
	taken2 := map[int]bool{80: true, 8443: true, 2053: true, apiPort: true}
	if p := pickPort(8443, taken2); p != 2087 {
		t.Errorf("want 2087 fallback, got %d", p)
	}
	// never returns the panel port
	taken3 := map[int]bool{}
	for _, p := range []int{8443, 2053, 2087, 2095, 8880, 2082, 2086, 2052, 8444, 9443, 2054, 2055} {
		taken3[p] = true
	}
	taken3[80] = true
	if p := pickPort(8443, taken3); p == 80 {
		t.Error("must never pick the panel HTTP port")
	}
}

// ─────────── 6) sub endpoint: base64 of 3 links + headers ───────────

func TestSubEndpoint(t *testing.T) {
	freshLoad(t)
	initReality()
	tok := subToken(mainUUID())
	req := httptest.NewRequest("GET", "http://16.171.14.5/sub/"+tok, nil)
	rec := httptest.NewRecorder()
	handleSub(rec, req, tok)
	if rec.Code != 200 {
		t.Fatalf("sub status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content type %q", ct)
	}
	if ui := rec.Header().Get("Subscription-Userinfo"); !strings.Contains(ui, "upload=") {
		t.Errorf("userinfo header missing: %q", ui)
	}
	if pv := rec.Header().Get("Profile-Update-Interval"); pv == "" {
		t.Error("update interval header missing")
	}
	dec, err := base64.StdEncoding.DecodeString(rec.Body.String())
	if err != nil {
		t.Fatalf("sub body not base64: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(dec)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 links in sub, got %d", len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "vless://") {
			t.Errorf("bad link: %s", l)
		}
	}
}

// ─────────── 7) client JSON (?fmt=xray): reality + mux off ───────────

func TestClientConfigJSON(t *testing.T) {
	freshLoad(t)
	initReality()
	c := &Client{Name: "main", ID: mainUUID()}
	cfg := clientConfigJSON(c, "16.171.14.5")
	if _, hasErr := cfg["error"]; hasErr {
		t.Fatalf("client config error: %v", cfg["error"])
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	for _, want := range []string{
		`"security":"reality"`, `"publicKey":"` + realityPub + `"`,
		`"fingerprint":"chrome"`, `"flow":"xtls-rprx-vision"`,
		`"serviceName":"dn"`, `"path":"/dn"`, `"enabled":false`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("client json missing %s", want)
		}
	}
}

// ─────────── 8) QR ASCII ───────────

func TestQRASCII(t *testing.T) {
	out, err := qrASCII("http://16.171.14.5/sub/abcdef0123456789abcdef0123456789", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 200 {
		t.Errorf("qr ascii too short: %d", len(out))
	}
	if !strings.Contains(out, "\n") {
		t.Error("qr ascii must be multi-line")
	}
}

// ─────────── 9) effective ports resolve without collisions ───────────

func TestEffectivePortsDistinct(t *testing.T) {
	freshLoad(t)
	p := effectivePorts()
	if p.Vision == p.XHTTP || p.Vision == p.GRPC || p.XHTTP == p.GRPC {
		t.Errorf("ports collide: %+v", p)
	}
	if p.Vision < 1024 || p.XHTTP < 1024 || p.GRPC < 1024 {
		t.Errorf("ports must be >=1024: %+v", p)
	}
}

// ─────────── 10) profile update flow ───────────

func TestProfileUpdate(t *testing.T) {
	freshLoad(t)
	// claim first
	body := `{"first":"علی","last":"رضایی","user":"ali","pass":"pass12345"}`
	req := httptest.NewRequest("POST", "/panel/api/setup", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleSetup(rec, req)
	if rec.Code != 200 {
		t.Fatal("claim failed")
	}
	// change password with WRONG current pass → 403
	bad := `{"current_pass":"WRONG","pass":"newpass12345"}`
	breq := httptest.NewRequest("POST", "/panel/api/profile", strings.NewReader(bad))
	brec := httptest.NewRecorder()
	handleProfileUpdate(brec, breq)
	if brec.Code != 403 {
		t.Errorf("wrong current pass must 403, got %d", brec.Code)
	}
	// correct flow
	good := `{"current_pass":"pass12345","pass":"newpass12345","first":"علی‌اکبر"}`
	greq := httptest.NewRequest("POST", "/panel/api/profile", strings.NewReader(good))
	grec := httptest.NewRecorder()
	handleProfileUpdate(grec, greq)
	if grec.Code != 200 {
		t.Errorf("profile update failed: %d %s", grec.Code, grec.Body.String())
	}
	stateMu.RLock()
	prof := state.Profile
	stateMu.RUnlock()
	if hashPass("newpass12345", prof.PassSalt) != prof.PassHash {
		t.Error("new password not active")
	}
	if prof.First != "علی‌اکبر" {
		t.Errorf("first name not updated: %q", prof.First)
	}
}

// ─────────── 11) v3.26 native state round-trip ───────────

func TestNativeStateRoundTrip(t *testing.T) {
	freshLoad(t)
	stateMu.Lock()
	state.Profile = &Profile{First: "A", Last: "B", User: "ab", PassSalt: "s", PassHash: "x", ClaimedAt: time.Now().Unix()}
	state.Clients = append(state.Clients, &Client{Name: "n", ID: "id1", CreatedAt: time.Now().Unix()})
	saveStateLocked()
	stateMu.Unlock()

	state = nil
	loadState()
	if !profileClaimed() {
		t.Fatal("claimed profile lost after reload")
	}
	if len(state.Clients) != 2 { // main + n
		t.Errorf("clients lost: %d", len(state.Clients))
	}
}

// ─────────── 12) rahnama + banner render ───────────

func TestBannerAndRahnama(t *testing.T) {
	freshLoad(t)
	initReality()
	b := bannerText()
	if !strings.Contains(b, "DEEP NETWORK v"+Version) {
		t.Error("banner missing version")
	}
	if !strings.Contains(b, "Vision") || !strings.Contains(b, "XHTTP") || !strings.Contains(b, "gRPC") {
		t.Error("banner missing transports")
	}
	r := rahnamaText()
	if !strings.Contains(r, "gstatic") {
		t.Error("rahnama missing the -1 fix")
	}
	if !strings.Contains(r, "reset-pass") {
		t.Error("rahnama missing reset-pass")
	}
}

// ─────────── 13) sub-list & doctor client config paths ───────────

func TestSubListAndDoctorConfig(t *testing.T) {
	freshLoad(t)
	subs := subList()
	if len(subs) == 0 {
		t.Fatal("sub list empty")
	}
	initReality()
	cfg := doctorClientConfig(mainUUID(), "16.171.14.5", "grpc", 2087, "www.bing.com", 20808)
	b, _ := json.Marshal(cfg)
	if !strings.Contains(string(b), `"serviceName":"dn"`) {
		t.Error("doctor grpc config missing serviceName")
	}
	if !strings.Contains(string(b), `"security":"reality"`) {
		t.Error("doctor config missing reality")
	}
}

var _ = filepath.Join
var _ = http.MethodGet
