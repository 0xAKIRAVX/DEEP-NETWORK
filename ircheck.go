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

// irCheckEdge TCP-probes one edge IP from all Iranian nodes; returns the
// success count (-1 = check-host unavailable).
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

// irCheckDomain HTTP-fetches the panel domain from all Iranian nodes and
// classifies: 1 = at least one node reached the panel, 2 = none did
// (DNS-poisoned / blocked / unreachable), 0 = probe unavailable.
func irCheckDomain(domain string) int {
        nodes := irNodeList()
        if len(nodes) == 0 {
                return 0
        }
        res := irPoll("http", "https://"+domain+"/panel/", nodes)
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

// irProbeAll updates IROk on the current top edges + the domain verdict.
// Runs after each scan; every failure degrades silently (status stays "؟").
func irProbeAll() {
        nodes := irNodeList()
        if len(nodes) == 0 {
                return
        }
        stateMu.RLock()
        domain := autoScanDomain()
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
        // per-edge TCP reachability (sequential: polite with the free API)
        for _, ip := range edges {
                ok := irCheckEdge(ip)
                if ok < 0 {
                        continue
                }
                stateMu.Lock()
                for _, e := range state.TopEdges {
                        if e.IP == ip {
                                e.IROk = ok
                                e.IRAt = time.Now().Unix()
                        }
                }
                stateMu.Unlock()
        }
        stateMu.Lock()
        saveStateLocked()
        stateMu.Unlock()
}
