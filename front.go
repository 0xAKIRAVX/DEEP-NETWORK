package main

// ─────────── v3.15: جلوی SNI / SNI front ───────────
// WHY THIS EXISTS (measured, not theory): the panel domain family is
// DNS-poisoned inside Iran (check-host probes from 6 Iranian nodes resolve it
// to 185.111.111.15x blocklist IPs) while the bunny edge IPs themselves stay
// TCP-reachable from all of them. Every subscription link therefore carries a
// literal IP address — but the TLS SNI still contained the panel domain, and
// the DPI kills those handshakes.
//
// THE FIX: bunny's edges serve a SHARED, publicly-trusted wildcard certificate
// (*.b-cdn.net) for any SNI they do not specifically know, and routing is done
// by the Host header. So the links can present SNI = <random>.b-cdn.net
// (valid certificate — strict TLS passes, no allowInsecure needed) while the
// encrypted Host header keeps routing to the panel. The DPI no longer sees the
// panel domain anywhere on the wire.
//
// The front is PROVEN before it is applied: frontProbe() does a strict TLS
// handshake (certificate must match the front name) and then a real
// Host-routed request that must be answered by THIS panel. Auto mode re-proves
// it on every scan; the admin can pin a custom front domain or switch it off.

import (
        "bufio"
        "crypto/tls"
        "fmt"
        "net"
        "net/http"
        "strings"
        "time"
)

// frontCandidates are tried in order (auto mode): shared bunny wildcard first
// (its random-label form defeats exact-name blocklists), then bunny's apex.
var frontCandidates = []struct {
        base string
        rand bool
}{
        {"b-cdn.net", true},
        {"bunny.net", false},
}

// frontName renders the concrete TLS SNI for one link emission.
func frontName(base string, rand bool) string {
        if rand {
                return "ng" + randHex(5) + "." + base
        }
        return base
}

// frontProbe proves one front candidate against an edge IP:
//   1. strict TLS handshake — the served certificate must cover the front
//      name (no allowInsecure anywhere);
//   2. a real request with Host: <domain> must be answered by this panel
//      (any non-5xx status line proves the routing).
func frontProbe(edgeIP, domain, base string, rand bool) error {
        sni := frontName(base, rand)
        d := &net.Dialer{Timeout: 6 * time.Second}
        conn, err := tls.DialWithDialer(d, "tcp", edgeIP+":443", &tls.Config{
                ServerName: sni,
                // strict verification — this is exactly what users' cores do
        })
        if err != nil {
                return fmt.Errorf("TLS: %v", err)
        }
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(8 * time.Second))
        req, _ := http.NewRequest(http.MethodGet, "http://"+domain+"/panel/", nil)
        req.Host = domain
        if err := req.Write(conn); err != nil {
                return fmt.Errorf("write: %v", err)
        }
        br := bufio.NewReader(conn)
        resp, err := http.ReadResponse(br, req)
        if err != nil {
                return fmt.Errorf("read: %v", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode >= 500 {
                return fmt.Errorf("edge answered %d", resp.StatusCode)
        }
        return nil
}

// applyFront is the pure, LOCK-FREE composition kept for unit tests — it must
// never be called on the global state while holding stateMu (v3.16: the
// production call sites use chooseFront + applyFrontChoice so the network
// probe runs with no lock held anywhere).
func applyFront(st *State, mode string, probe func(base string, rand bool) error) (applied string) {
        base, rand := chooseFront(mode, probe)
        applyFrontChoice(st, base, rand)
        return base
}

// chooseFront is the decision half (network probe, NO state access — must be
// called with NO stateMu held): mode "" (auto) walks frontCandidates in order;
// "off" disables; any other value is a custom base domain ("*.x" implies a
// random label).
func chooseFront(mode string, probe func(base string, rand bool) error) (string, bool) {
        mode = strings.ToLower(strings.TrimSpace(mode))
        if mode == "off" {
                return "", false
        }
        if mode != "" && mode != "auto" {
                base := strings.TrimPrefix(strings.TrimPrefix(mode, "*."), ".")
                rand := strings.HasPrefix(mode, "*") || strings.HasPrefix(mode, ".")
                if probe(base, rand) == nil {
                        return base, rand
                }
                return "", false
        }
        for _, cand := range frontCandidates {
                if probe(cand.base, cand.rand) == nil {
                        return cand.base, cand.rand
                }
        }
        return "", false
}

// applyFrontChoice is the state-write half — caller MUST hold stateMu.
// ("", false) clears the front.
func applyFrontChoice(st *State, base string, rand bool) {
        if base == "" {
                st.FrontSNI, st.FrontRand, st.FrontAt = "", false, 0
                return
        }
        st.FrontSNI, st.FrontRand, st.FrontAt = base, rand, time.Now().Unix()
}

// frontFromState renders the current front SNI ("" = no front).
func frontFromState() string {
        stateMu.RLock()
        base, rand := state.FrontSNI, state.FrontRand
        stateMu.RUnlock()
        if base == "" {
                return ""
        }
        return frontName(base, rand)
}
