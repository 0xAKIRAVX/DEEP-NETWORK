package main

import (
	"strings"
	"testing"
	"time"
)

// ─────────── v3.15: SNI front + hourly scan + doctor config ───────────

func TestLinkSNIUsesFront(t *testing.T) {
	st := &State{RandomSNI: true}
	save := state
	state = st
	defer func() { state = save }()

	host := "deep-network-development-w4a86.lucity.app"

	// legacy: random lucity subdomain
	legacy := linkSNI(host)
	if !strings.HasPrefix(legacy, "ng") || !strings.HasSuffix(legacy, ".lucity.app") {
		t.Fatalf("legacy SNI = %q, want ng…lucity.app", legacy)
	}

	// front active (wildcard): random label under the front base
	stateMu.Lock()
	st.FrontSNI, st.FrontRand = "b-cdn.net", true
	stateMu.Unlock()
	fronted := linkSNI(host)
	if !strings.HasPrefix(fronted, "ng") || !strings.HasSuffix(fronted, ".b-cdn.net") {
		t.Fatalf("fronted SNI = %q, want ng…b-cdn.net", fronted)
	}

	// front active (exact, e.g. bunny.net): the bare name, no random label
	stateMu.Lock()
	st.FrontSNI, st.FrontRand = "bunny.net", false
	stateMu.Unlock()
	if got := linkSNI(host); got != "bunny.net" {
		t.Fatalf("exact front SNI = %q, want bunny.net", got)
	}

	// front cleared → legacy again
	stateMu.Lock()
	st.FrontSNI, st.FrontRand = "", false
	stateMu.Unlock()
	if got := linkSNI(host); !strings.HasSuffix(got, ".lucity.app") {
		t.Fatalf("post-clear SNI = %q, want lucity.app", got)
	}
}

func TestApplyFrontModes(t *testing.T) {
	probeOK := func(base string, rand bool) error { return nil }
	probeFail := func(base string, rand bool) error { return errFake }

	// auto: first candidate wins (v3.17: fonts.bunny.net — IR-proven order)
	st := &State{}
	if got := applyFront(st, "", probeOK); got != "fonts.bunny.net" {
		t.Fatalf("auto front = %q, want fonts.bunny.net", got)
	}
	if st.FrontRand || st.FrontSNI != "fonts.bunny.net" || st.FrontAt == 0 {
		t.Fatalf("auto state wrong: %+v", st)
	}

	// auto with failing probe: front cleared
	st2 := &State{FrontSNI: "b-cdn.net", FrontRand: true, FrontAt: 42}
	if got := applyFront(st2, "", probeFail); got != "" {
		t.Fatalf("failing probe front = %q, want empty", got)
	}
	if st2.FrontSNI != "" || st2.FrontAt != 0 {
		t.Fatalf("failing probe must clear front: %+v", st2)
	}

	// off: always cleared
	st3 := &State{FrontSNI: "b-cdn.net", FrontRand: true, FrontAt: 42}
	if got := applyFront(st3, "off", probeOK); got != "" || st3.FrontSNI != "" {
		t.Fatalf("off must clear: %+v", st3)
	}

	// custom wildcard form
	st4 := &State{}
	if got := applyFront(st4, "*.myfront.example", probeOK); got != "myfront.example" {
		t.Fatalf("custom wildcard front = %q, want myfront.example", got)
	}
	if !st4.FrontRand {
		t.Error("*. prefix implies random label")
	}

	// custom exact form
	st5 := &State{}
	if got := applyFront(st5, "myfront.example", probeOK); got != "myfront.example" {
		t.Fatalf("custom exact front = %q", got)
	}
	if st5.FrontRand {
		t.Error("exact custom must not be random")
	}

	// custom that fails the probe → cleared
	st6 := &State{}
	if got := applyFront(st6, "broken.example", probeFail); got != "" || st6.FrontSNI != "" {
		t.Fatalf("failing custom must not apply: %+v", st6)
	}
}

func TestAutoScanIntervalClamped(t *testing.T) {
	save := state
	defer func() { state = save }()
	for _, tc := range []struct {
		set  int
		want time.Duration
	}{
		{0, time.Hour}, // default 1h
		{1, time.Hour}, // user request: hourly
		{3, 3 * time.Hour},
		{24, 24 * time.Hour},
		{48, 24 * time.Hour}, // clamp high
		{-5, time.Hour},      // clamp low
	} {
		state = &State{AutoScanHours: tc.set}
		if got := autoScanInterval(); got != tc.want {
			t.Errorf("AutoScanHours=%d → %v, want %v", tc.set, got, tc.want)
		}
	}
}

func TestDoctorClientConfigShape(t *testing.T) {
	c := &Client{Name: "main", ID: "6c4abbe-e645-40fa-bf1b-84deac7cbc1a"}
	stateMu.Lock()
	state.FrontSNI, state.FrontRand = "b-cdn.net", true
	stateMu.Unlock()
	defer func() { stateMu.Lock(); state.FrontSNI, state.FrontRand = "", false; stateMu.Unlock() }()
	domain := "deep-network-development-w4a86.lucity.app"
	injectOrigin(t, domain, "84.17.37.214", "Frankfurt", "DE")

	for _, key := range doctorKeys {
		cfg, err := doctorClientConfig(c, key, "185.102.217.65", domain, 27123)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		obs, _ := cfg["outbounds"].([]map[string]any)
		if len(obs) != 1 {
			t.Fatalf("%s: want 1 outbound, got %d", key, len(obs))
		}
		stream, _ := obs[0]["streamSettings"].(map[string]any)
		tls, _ := stream["tlsSettings"].(map[string]any)
		sni, _ := tls["serverName"].(string)
		// v3.21.2: every edge transport keeps the front SNI, except
		// XHTTP — it now dials the origin directly with the panel
		// domain as SNI (bunny's h2 layer stalls its stream tails).
		if key == "vless-xhttp" {
			if sni != domain {
				t.Errorf("xhttp doctor SNI = %q, want origin domain %q", sni, domain)
			}
			vs, _ := obs[0]["settings"].(map[string]any)
			vn, _ := vs["vnext"].([]map[string]any)
			if len(vn) == 1 && vn[0]["address"] != "84.17.37.214" {
				t.Errorf("xhttp doctor must dial the origin IP, got %v", vn[0]["address"])
			}
		} else if !strings.HasSuffix(sni, ".b-cdn.net") {
			t.Errorf("%s: doctor SNI = %q, want front", key, sni)
		}
		if v, ok := tls["allowInsecure"]; ok && v == true {
			t.Errorf("%s: allowInsecure must never be set", key)
		}
		netw, _ := stream["network"].(string)
		if netw == "" {
			t.Errorf("%s: network empty", key)
		}
		var hostHdr string
		switch ws := stream["wsSettings"].(type) {
		case map[string]any:
			hdrs, _ := ws["headers"].(map[string]any)
			hostHdr, _ = hdrs["Host"].(string)
		}
		if hostHdr != "" && !strings.HasSuffix(hostHdr, "lucity.app") {
			t.Errorf("%s: Host routing header = %q, want panel host", key, hostHdr)
		}
	}
	if _, err := doctorClientConfig(c, "vless-bogus", "1.2.3.4", "x.example", 1); err == nil {
		t.Error("unknown transport must error")
	}
}

func TestKitTextMentionsFrontAndHourly(t *testing.T) {
	save := state
	state = &State{FrontSNI: "b-cdn.net", FrontRand: true, Clients: []*Client{}}
	defer func() { state = save }()
	stateMu.Lock()
	state.FrontSNI, state.FrontRand = "b-cdn.net", true
	stateMu.Unlock()
	kit := localModeKitText("deep-network-development-w4a86.lucity.app")
	stateMu.Lock()
	state.FrontSNI, state.FrontRand = "", false
	stateMu.Unlock()
	if !strings.Contains(kit, "b-cdn.net") {
		t.Error("kit must mention the active front")
	}
	if !strings.Contains(kit, "۱ ساعت") {
		t.Error("kit must state the hourly scan cadence")
	}
	if strings.Contains(kit, "SNI سفید") {
		t.Error("kit must not advertise the removed white-SNI variant")
	}
}

// fakeErr is a sentinel error for the probe-failure paths.
type fakeErr struct{}

func (*fakeErr) Error() string { return "fake probe failure" }

var errFake = &fakeErr{}
