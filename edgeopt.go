package main

// edgeopt.go — v3.9.0 "همه‌اپراتوره" (All-Operator Optimization)
//
// The v3.6 optimizer minimized ONLY the browser→edge RTT and applied ONE fixed
// IP for every user on every operator. Two failure modes followed:
//   1. "پینگ بالا" — the edge→origin leg (bunny PoP → Lucity app server) was
//      never measured, so a near-user PoP with a terrible origin path could win.
//   2. "کانفیگ کار نمی‌کنه" — one IP for all operators means users on operators
//      that route badly to that PoP (or DPI-block its SNI) lose EVERYTHING.
//
// v3.9 fixes both:
//   • per-edge quality gate measured from BOTH ends:
//       - browser: median RTT, jitter, PACKET LOSS (6 probes)
//       - server:  edge→origin TLS handshake ms + throughput (kbps through the
//         real CDN path, fetched with SNI/Host = the panel domain)
//   • score = user RTT + 0.35×origin RTT + 0.5×jitter, loss==0 required
//   • the subscription then carries the TOP-5 edges + the DNS-auto entry, so
//     every client app (v2rayNG / Hiddify / Streisand…) picks ITS best entry
//     per operator — zero reconfiguration, works on all operators.

import (
        "crypto/tls"
        "fmt"
        "net"
        "net/http"
        "sort"
        "strconv"
        "strings"
        "sync"
        "time"
)

// ─────────── /panel/api/speedblob — public N-KB payload for path tests ───────────

func handleSpeedBlob(w http.ResponseWriter, r *http.Request) {
        n := 64
        if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("n"))); err == nil && v > 0 {
                if v > 512 {
                        v = 512
                }
                n = v
        }
        buf := make([]byte, 1024) // zeros
        w.Header().Set("Content-Type", "application/octet-stream")
        w.Header().Set("Cache-Control", "no-store")
        // v3.21.2: chunked=1 streams WITHOUT Content-Length, flushed every
        // 4KB — the doctor's completion probe rides this so a transport that
        // handshakes but never delivers the stream tail (bunny h2 + XHTTP,
        // 2026-10-25) FAILS the doctor instead of shipping to users.
        if r.URL.Query().Get("chunked") == "1" {
                flusher, _ := w.(http.Flusher)
                for i := 0; i < n; i += 4 {
                    k := 4
                    if i+4 > n {
                        k = n - i
                    }
                    for j := 0; j < k; j++ {
                        if _, err := w.Write(buf); err != nil {
                            return
                        }
                    }
                    if flusher != nil {
                        flusher.Flush()
                    }
                }
                return
        }
        w.Header().Set("Content-Length", strconv.Itoa(n*1024))
        for i := 0; i < n; i++ {
                if _, err := w.Write(buf); err != nil {
                        return
                }
        }
}

// ─────────── /panel/api/edgespeed — server-side edge→origin quality ───────────

type edgeSpeedResult struct {
        IP   string  `json:"ip"`
        OK   bool    `json:"ok"`
        HsMs float64 `json:"hs_ms"` // TCP+TLS handshake to the edge (≈origin→edge RTT×2)
        DlMs float64 `json:"dl_ms"` // full download of kb KB through edge→origin→edge
        Kbps float64 `json:"kbps"`  // effective KB/s through this edge
}

type edgeSpeedCacheEntry struct {
        res     edgeSpeedResult
        expires time.Time
}

var (
        edgeSpeedMu    sync.Mutex
        edgeSpeedCache = map[string]edgeSpeedCacheEntry{}
)

// measureEdgeSpeed dials the edge IP directly but speaks TLS with the panel
// domain as SNI and Host — exactly what a real client config does — then
// downloads the speedblob through it. This is the true edge→origin path.
func measureEdgeSpeed(ip, domain string, kb int, timeout time.Duration) edgeSpeedResult {
        if kb < 8 {
                kb = 8
        }
        if kb > 256 {
                kb = 256
        }
        out := edgeSpeedResult{IP: ip}
        d := net.Dialer{Timeout: timeout}
        t0 := time.Now()
        raw, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
        if err != nil {
                return out
        }
        defer raw.Close()
        conn := tls.Client(raw, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
        if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
                return out
        }
        if err := conn.Handshake(); err != nil {
                return out
        }
        out.HsMs = round1(float64(time.Since(t0).Microseconds()) / 1000.0)
        // handshake success = the edge is reachable AND serves this zone's TLS cert.
        // (Throughput may still be 0 when the origin rejects the blob path — e.g. the
        // live deploy still being an older version — hs_ms remains a valid metric.)
        out.OK = true

        req := "GET /panel/api/speedblob?n=" + itoa(kb) + " HTTP/1.1\r\nHost: " + domain +
                "\r\nUser-Agent: DeepNetwork/" + Version + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        t1 := time.Now()
        if _, err := conn.Write([]byte(req)); err != nil {
                return out
        }
        nread := 0
        buf := make([]byte, 16384)
        for {
                n, err := conn.Read(buf)
                nread += n
                if err != nil || n == 0 {
                        break
                }
        }
        dl := time.Since(t1)
        out.DlMs = round1(float64(dl.Microseconds()) / 1000.0)
        if out.DlMs > 0 && nread > kb*512 { // body mostly arrived (status line eats some)
                if ms := float64(dl.Milliseconds()); ms > 0 {
                        out.Kbps = round1(float64(kb) * 1000.0 / ms)
                }
        }
        return out
}

func handleEdgeSpeed(w http.ResponseWriter, r *http.Request) {
        d := readJSONBody(r)
        raw, _ := d["targets"].([]any)
        domain := strings.TrimSpace(osGetenv("DOMAIN"))
        if domain == "" {
                domain = requestHost(r)
        }
        if domain == "" || isIPLiteral(domain) || !hostRe.MatchString(domain) {
                sendJSON(w, 400, map[string]any{"error": "دامنه عمومی سرویس پیدا نشد"})
                return
        }
        kb := int(jint(d, "kb"))
        if kb < 8 || kb > 256 {
                kb = 64
        }
        var ips []string
        seen := map[string]bool{}
        for _, x := range raw {
                if s, ok := x.(string); ok && isValidScanTarget(s) && !seen[s] {
                        seen[s] = true
                        ips = append(ips, s)
                        if len(ips) >= 24 {
                                break
                        }
                }
        }
        if len(ips) == 0 {
                sendJSON(w, 400, map[string]any{"error": "هدفی برای سنجش سرعت وارد نشده است"})
                return
        }

        results := make([]edgeSpeedResult, len(ips))
        sem := make(chan struct{}, 8)
        var wg sync.WaitGroup
        now := time.Now()
        for i, ip := range ips {
                wg.Add(1)
                go func(i int, ip string) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()
                        edgeSpeedMu.Lock()
                        c, hit := edgeSpeedCache[ip]
                        edgeSpeedMu.Unlock()
                        if hit && now.Before(c.expires) && c.res.Kbps > 0 {
                                results[i] = c.res
                                return
                        }
                        res := measureEdgeSpeed(ip, domain, kb, 6*time.Second)
                        results[i] = res
                        edgeSpeedMu.Lock()
                        edgeSpeedCache[ip] = edgeSpeedCacheEntry{res: res, expires: time.Now().Add(60 * time.Second)}
                        edgeSpeedMu.Unlock()
                }(i, ip)
        }
        wg.Wait()
        sendJSON(w, 200, map[string]any{"results": results, "count": len(results), "kb": kb})
}

// ─────────── top_edges settings parsing (handleSettings) ───────────

// parseTopEdges sanitizes the admin/optimizer supplied edge list:
// IP-literals only (that is what a CDN edge is), max 6, sorted by score.
func parseTopEdges(v any) []*EdgeScore {
        raw, ok := v.([]any)
        if !ok {
                return nil
        }
        var out []*EdgeScore
        seen := map[string]bool{}
        for _, x := range raw {
                m, ok := x.(map[string]any)
                if !ok {
                        continue
                }
                ip := strings.TrimSpace(fmt.Sprintf("%v", m["ip"]))
                if ip == "" || !isIPLiteral(ip) || seen[ip] || !validAddress(ip) {
                        continue
                }
                seen[ip] = true
                e := &EdgeScore{IP: ip, TS: time.Now().Unix()}
                e.Med = clampF(toF64(m["med"]), 0, 5000)
                e.Jit = clampF(toF64(m["jit"]), 0, 5000)
                e.Loss = clampF(toF64(m["loss"]), 0, 100)
                e.OriginMs = clampF(toF64(m["origin_ms"]), 0, 5000)
                e.SpeedKbps = clampF(toF64(m["kbps"]), 0, 100000)
                e.Score = clampF(toF64(m["score"]), 0, 10000)
                e.CC = trunc(fmt.Sprintf("%v", m["cc"]), 2)
                e.City = trunc(fmt.Sprintf("%v", m["city"]), 40)
                if e.City == "<nil>" {
                        e.City = ""
                }
                out = append(out, e)
                if len(out) >= 6 {
                        break
                }
        }
        sort.SliceStable(out, func(i, j int) bool {
                if out[i].Loss != out[j].Loss {
                        return out[i].Loss < out[j].Loss
                }
                if out[i].Score != out[j].Score {
                        return out[i].Score < out[j].Score
                }
                return out[i].Med < out[j].Med
        })
        return out
}

func toF64(v any) float64 {
        switch x := v.(type) {
        case float64:
                return x
        case int:
                return float64(x)
        case int64:
                return float64(x)
        case string:
                f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
                return f
        }
        return 0
}

func clampF(v, lo, hi float64) float64 {
        if v < lo {
                return lo
        }
        if v > hi {
                return hi
        }
        return v
}
