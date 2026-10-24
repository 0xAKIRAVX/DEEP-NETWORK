package main

// ─────────── v3.15: تست دسترسی از ایران / Iran vantage probes ───────────
// The scanner grades edges from the PANEL's vantage — but users sit behind
// Iranian ISPs. check-host.net exposes probe nodes inside Iran; the panel asks
// them to TCP-connect the top edges (IP-block check) and to fetch the panel
// domain (DNS-poisoning check — this is exactly how we proved lucity.app is
// poisoned to 185.111.111.15x inside Iran while the edge IPs stay reachable).

import (
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "strings"
        "sync"
        "time"
)

const (
        checkHostAPI  = "https://check-host.net"
        irCacheEvery  = 24 * time.Hour
        irPollEvery   = 5 * time.Second
        irPollTimeout = 55 * time.Second
        irMaxEdges    = 5
)

var (
        irNodeMu     sync.Mutex
        irNodeCache  []string
        irNodeCached time.Time
)

// irNodeList returns check-host's Iranian probe nodes (cached 24h).
func irNodeList() []string {
        irNodeMu.Lock()
        defer irNodeMu.Unlock()
        if len(irNodeCache) > 0 && time.Since(irNodeCached) < irCacheEvery {
                return irNodeCache
        }
        req, _ := http.NewRequest(http.MethodGet, checkHostAPI+"/nodes/hosts", nil)
        req.Header.Set("Accept", "application/json")
        req.Header.Set("User-Agent", "dn-panel/3.15")
        cli := &http.Client{Timeout: 20 * time.Second}
        resp, err := cli.Do(req)
        if err != nil {
                return irNodeCache
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        var data struct {
                Nodes map[string]struct {
                        Country string `json:"country"`
                } `json:"nodes"`
        }
        if json.Unmarshal(body, &data) != nil {
                return irNodeCache
        }
        var out []string
        for name, info := range data.Nodes {
                cc := strings.ToUpper(strings.TrimSpace(info.Country))
                if cc == "IR" || strings.HasPrefix(strings.ToLower(name), "ir") {
                        out = append(out, name)
                }
        }
        if len(out) > 0 {
                irNodeCache, irNodeCached = out, time.Now()
        }
        return irNodeCache
}

// irSubmit posts one check; irResult polls it once (nil = still pending).
func irSubmit(kind, target string, nodes []string) (string, error) {
        q := url.Values{}
        q.Set("host", target)
        for _, n := range nodes {
                q.Add("node", n)
        }
        req, _ := http.NewRequest(http.MethodGet, checkHostAPI+"/check-"+kind+"?"+q.Encode(), nil)
        req.Header.Set("Accept", "application/json")
        req.Header.Set("User-Agent", "dn-panel/3.15")
        cli := &http.Client{Timeout: 20 * time.Second}
        resp, err := cli.Do(req)
        if err != nil {
                return "", err
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        var data struct {
                RequestID string `json:"request_id"`
        }
        if err := json.Unmarshal(body, &data); err != nil || data.RequestID == "" {
                return "", fmt.Errorf("bad submit reply")
        }
        return data.RequestID, nil
}

func irResult(rid string) (map[string]json.RawMessage, error) {
        req, _ := http.NewRequest(http.MethodGet, checkHostAPI+"/check-result/"+rid, nil)
        req.Header.Set("Accept", "application/json")
        req.Header.Set("User-Agent", "dn-panel/3.15")
        cli := &http.Client{Timeout: 20 * time.Second}
        resp, err := cli.Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        var data map[string]json.RawMessage
        if err := json.Unmarshal(body, &data); err != nil {
                return nil, err
        }
        return data, nil
}

// irPoll submits and polls until all nodes answered or the timeout hits.
func irPoll(kind, target string, nodes []string) map[string]json.RawMessage {
        rid, err := irSubmit(kind, target, nodes)
        if err != nil || rid == "" {
                return nil
        }
        deadline := time.Now().Add(irPollTimeout)
        for time.Now().Before(deadline) {
                time.Sleep(irPollEvery)
                res, err := irResult(rid)
                if err != nil || res == nil {
                        continue
                }
                all := true
                for _, n := range nodes {
                        if raw, ok := res[n]; !ok || string(raw) == "null" {
                                all = false
                                break
                        }
                }
                if all {
                        return res
                }
        }
        return nil
}

// irCheckEdgeTCP-probes one edge IP from all Iranian nodes; returns the
// success count (-1 = check-host unavailable). v3.18: superseded for gating
// by irCheckEdgeTLS (bare TCP proved meaningless — dead edges answered SYN
// 6/6); kept for ad-hoc diagnostics.
func irCheckEdge(ip string) int {
        nodes := irNodeList()
        if len(nodes) == 0 {
                return -1
        }
        res := irPoll("tcp", ip+":443", nodes)
        if res == nil {
                return -1
        }
        ok := 0
        for _, raw := range res {
                var v []struct {
                        Address string  `json:"address"`
                        Time    float64 `json:"time"`
                }
                if json.Unmarshal(raw, &v) == nil && len(v) > 0 && v[0].Address != "" {
                        ok++
                }
        }
        return ok
}

// irCheckEdgeTLS does a REAL TLS handshake + HTTP request to https://<ip>/
// from every Iranian node (v3.18). TCP-reachable is NOT enough: every PoP the
// users reported as -1 (Bucharest RO / Karbala IQ / EdgeUno-Istanbul / the
// panel's own 185.111.111.x geo answer) accepted TCP from all 6 IR nodes but
// timed out the moment a TLS ClientHello arrived — while the Frankfurt
// primary kept working for real users. Any HTTP answer (even 403/404/421 —
// bunny's error pages) proves the TLS handshake completed; all-nodes-fail =
// the edge is TLS-dead from Iran and must never ride a subscription.
func irCheckEdgeTLS(ip string) int {
        return irCheckURL("https://" + ip + "/")
}

// irCheckDomain HTTP-fetches the panel domain from all Iranian nodes and
// classifies: 1 = at least one node reached the panel, 2 = none did
// (DNS-poisoned / blocked / unreachable), 0 = probe unavailable.
func irCheckDomain(domain string) int {
        return irCheckURL("https://" + domain + "/panel/")
}

// irCheckURL HTTP-fetches any URL from all Iranian nodes and classifies:
// 1 = at least one node got an HTTP answer (TLS+SNI passed Iranian DPI),
// 2 = none did, 0 = probe unavailable. Used both for the panel domain and
// for the SNI front: bunny answers the shared-cert front hostname with a
// 404/421 error page — ANY HTTP answer still proves the SNI survives DPI.
func irCheckURL(rawurl string) int {
        nodes := irNodeList()
        if len(nodes) == 0 {
                return 0
        }
        res := irPoll("http", rawurl, nodes)
        if res == nil {
                return 0
        }
        for _, raw := range res {
                // check-http result row: [ [1, time, "OK...", code, ip], ... ]
                var row []json.RawMessage
                if json.Unmarshal(raw, &row) == nil && len(row) > 0 {
                        var arr []any
                        if json.Unmarshal(row[0], &arr) == nil && len(arr) >= 1 {
                                if f, ok := arr[0].(float64); ok && f == 1 {
                                        return 1
                                }
                        }
                }
        }
        return 2
}

// frontIRVerdict measures one front candidate from Iranian vantage points
// (any HTTP answer = the SNI completed a TLS handshake inside Iran).
func frontIRVerdict(base string, rand bool) int {
        return irCheckURL("https://" + frontName(base, rand) + "/")
}

// irProbeAll updates IROk on the current top edges + the domain verdict +
// the front candidates. Runs after each scan; every failure degrades silently
// (status stays "؟").
func irProbeAll() {
        // v3.16 CRITICAL FIX: autoScanDomain() takes stateMu itself, so it
        // MUST be resolved BEFORE the outer RLock below. The old order held
        // RLock and then called a function that takes RLock again — a
        // recursive RLock that DEADLOCKS the whole panel whenever a writer
        // queues in between (this is exactly what froze the live v3.15).
        domain := autoScanDomain()
        nodes := irNodeList()
        if len(nodes) == 0 {
                return
        }
        stateMu.RLock()
        var edges []string
        for i, e := range state.TopEdges {
                if i >= irMaxEdges {
                        break
                }
                edges = append(edges, e.IP)
        }
        stateMu.RUnlock()
        if domain == "" {
                return
        }
        // domain poisoning verdict
        if verdict := irCheckDomain(domain); verdict != 0 {
                stateMu.Lock()
                state.DomainIR = verdict
                state.DomainIRAt = time.Now().Unix()
                stateMu.Unlock()
        }
        // v3.17: refresh every proven front candidate from Iranian vantage
        // (skipped when the scan evaluated them seconds ago) and SELF-HEAL
        // the active front when it is blocked from every IR node while a
        // proven alternative survives — users should not wait an hour for
        // the next scan when the fix is already sitting in the picks.
        stateMu.RLock()
        picks := append([]FrontPick(nil), state.FrontPicks...)
        picksAt := state.FrontPicksAt
        activeBase := state.FrontSNI
        stateMu.RUnlock()
        if len(picks) > 0 && time.Now().Unix()-picksAt > 600 {
                for i := range picks {
                        if v := irCheckURL("https://" + frontName(picks[i].Base, picks[i].Rand) + "/"); v != 0 {
                                picks[i].IR, picks[i].At = v, time.Now().Unix()
                        }
                }
                var alive *FrontPick
                activeDead := false
                for i := range picks {
                        if picks[i].Base == activeBase && picks[i].IR == 2 {
                                activeDead = true
                        }
                        if picks[i].Base != activeBase && picks[i].IR == 1 && alive == nil {
                                alive = &picks[i]
                        }
                }
                stateMu.Lock()
                state.FrontPicks, state.FrontPicksAt = picks, time.Now().Unix()
                for i := range picks {
                        if picks[i].Base == activeBase && picks[i].IR >= 0 {
                                state.FrontIR, state.FrontIRAt = picks[i].IR, picks[i].At
                        }
                }
                saveStateLocked()
                stateMu.Unlock()
                if activeDead && alive != nil {
                        logf("front self-heal: %q blocked from Iran — switching to %q", activeBase, alive.Base)
                        switchToFront(*alive)
                        go doctorRun()
                }
        }
        // per-edge REAL-TLS reachability (v3.18: upgraded from bare TCP —
        // every edge the users reported as -1 was TCP-reachable 6/6 but
        // TLS-dead from Iran). IROk carries the same verdict for the UI chips.
        for _, ip := range edges {
                ok := irCheckEdgeTLS(ip)
                if ok < 0 {
                        continue
                }
                stateMu.Lock()
                for _, e := range state.TopEdges {
                        if e.IP == ip {
                                e.IROk = ok
                                e.IRAt = time.Now().Unix()
                                e.IRTLS = ok
                                e.IRTLSAt = e.IRAt
                        }
                }
                stateMu.Unlock()
        }
        stateMu.Lock()
        saveStateLocked()
        stateMu.Unlock()
}
