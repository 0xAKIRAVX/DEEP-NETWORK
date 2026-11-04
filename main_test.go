package main

// TestMain pins the deployment shape for the whole test binary.
//
// The panel now has two link/URL shapes (v3.24): CDN mode (Lucity/PaaS —
// the original) and VPS direct mode (bare IP, Reality first). The legacy
// suite exercises CDN behavior, and vpsMode() would flip to true whenever
// DOMAIN is unset — so CDN is pinned here for the binary, and the VPS-mode
// tests (v3240_test.go) opt back in with t.Setenv("DEPLOY_MODE", "vps").
//
// The one test that must NOT run under this pin is the banner smoke (it
// forces its own env).

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("DEPLOY_MODE", "cdn")
	os.Exit(m.Run())
}
