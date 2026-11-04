package main

// v3.24.0 tests: terminal banner — QR round-trip + URL logic.

import (
	"strings"
	"testing"
)

// TestQRTerminalRoundTrip renders a URL into half-block glyph rows, parses
// them back into the module matrix and compares with qrMatrix() — if this
// passes, the terminal QR is byte-for-byte the same QR the panel serves.
func TestQRTerminalRoundTrip(t *testing.T) {
	url := "http://185.120.10.5/sub/3c7d6574577be9d9c81844c31cf3a2f4"
	st := termStyle{on: true}
	out := qrTerminal(url, st)
	if out == "" {
		t.Fatal("qrTerminal returned empty output")
	}
	// strip ANSI + the 6-space indent, collect glyph rows
	var rows []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "\x1b[30;47m") {
			continue
		}
		clean := strings.ReplaceAll(strings.ReplaceAll(line, "\x1b[30;47m", ""), "\x1b[0m", "")
		rows = append(rows, strings.TrimPrefix(clean, "      "))
	}
	if len(rows) == 0 {
		t.Fatal("no QR rows rendered")
	}
	// rebuild the matrix: two glyph rows = one pair of module rows
	enc, err := qrEncode(url)
	if err != nil {
		t.Fatalf("qrEncode: %v", err)
	}
	want := qrMatrix(enc.v, enc.level, enc.cws)
	n := len(want)
	const quiet = 4
	size := n + 2*quiet
	if len(rows) != (size+1)/2 {
		t.Fatalf("row count: got %d want %d", len(rows), (size+1)/2)
	}
	if len([]rune(rows[0])) != size {
		t.Fatalf("row width: got %d want %d", len(rows[0]), size)
	}
	runeRows := make([][]rune, len(rows))
	for i, r := range rows {
		runeRows[i] = []rune(r)
	}
	get := func(r, c int) bool {
		ch := runeRows[r/2][c]
		top := ch == '█' || ch == '▀'
		bot := ch == '█' || ch == '▄'
		if r%2 == 0 {
			return top
		}
		return bot
	}
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			wantDark := false
			if r >= quiet && c >= quiet && r < size-quiet && c < size-quiet {
				wantDark = want[r-quiet][c-quiet]
			}
			if get(r, c) != wantDark {
				t.Fatalf("module mismatch at (%d,%d): glyph=%q want dark=%v", r, c, rows[r/2][c], wantDark)
			}
		}
	}
}

// TestQRTerminalPlainMode asserts no ANSI leaks when colors are off.
func TestQRTerminalPlainMode(t *testing.T) {
	out := qrTerminal("http://1.2.3.4/sub/abcdef0123456789abcdef0123456789", termStyle{on: false})
	if out == "" {
		t.Fatal("expected QR text even without colors")
	}
	if strings.Contains(out, "\x1b") {
		t.Fatal("plain mode must not emit ANSI")
	}
}

// TestPanelPublicURLBareIP verifies the v3.24 bugfix: bare-IP VPS mode must
// produce http://IP[:port], never the old (wrong) https://DOMAIN.
func TestPanelPublicURLBareIP(t *testing.T) {
	old := state
	state = nil
	defer func() { state = old }()
	cases := []struct {
		domain string
		port   string
		want   string
	}{
		{"185.120.10.5", "80", "http://185.120.10.5"},
		{"185.120.10.5", "8080", "http://185.120.10.5:8080"},
		{"deep-network-eco-7kpnz.lucity.app", "8080", "https://deep-network-eco-7kpnz.lucity.app"},
		{"", "9000", "http://localhost:9000"},
	}
	for _, c := range cases {
		t.Setenv("DOMAIN", c.domain)
		t.Setenv("PORT", c.port)
		if got := panelPublicURL(); got != c.want {
			t.Errorf("DOMAIN=%q PORT=%q: got %q want %q", c.domain, c.port, got, c.want)
		}
	}
}

// TestVisLenANSI checks the box padding math ignores escape sequences.
func TestVisLenANSI(t *testing.T) {
	st := termStyle{on: true}
	if n := visLen(st.c("1;33", "Password")); n != 8 {
		t.Errorf("visLen colored: got %d want 8", n)
	}
	if n := visLen("Password"); n != 8 {
		t.Errorf("visLen plain: got %d want 8", n)
	}
}
