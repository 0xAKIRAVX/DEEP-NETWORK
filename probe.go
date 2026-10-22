package main

import (
        "bytes"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "net/http"
        "os/exec"
        "path/filepath"
        "strconv"
        "strings"
        "sync"
        "time"
)

// ─────────── Rust prober (bin/deep-probe) + bunny CDN edge pipeline ───────────

type ProbeTarget struct {
        IP     string `json:"ip"`
        Port   int    `json:"port"`
        SNI    string `json:"sni,omitempty"`
        Rounds int    `json:"rounds,omitempty"`
}

type ProbeResult struct {
        Target string  `json:"target"`
        IP     string  `json:"ip,omitempty"`
        OK     bool    `json:"ok"`
        TCPMs  float64 `json:"tcp_ms"`
        TLSMs  float64 `json:"tls_ms"`
        SNIOk  bool    `json:"sni_ok"`
        SNIStat string `json:"sni_stat"`
}

type probeRequest struct {
        Targets   []ProbeTarget `json:"targets"`
        TimeoutMs int          `json:"timeout_ms"`
}

type probeResponse struct {
        Results []ProbeResult `json:"results"`
}

func deepProbeBin() string {
        for _, p := range []string{filepath.Join(appDir(), "bin", "deep-probe"), "/usr/local/bin/deep-probe", "deep-probe"} {
                if st, err := statFile(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
                        return p
                }
        }
        if p, err := exec.LookPath("deep-probe"); err == nil {
                return p
        }
        return ""
}

// runDeepProbe calls the Rust binary: fast parallel TCP + TLS-ClientHello probes.
// Line protocol: "<ip> <port> <sni> <rounds>" in, "<ip> <ok> <tcp_ms> <tls_ms> <stat>" out.
func runDeepProbe(targets []ProbeTarget, timeoutMs int) []ProbeResult {
        if timeoutMs <= 0 {
                timeoutMs = 2000
        }
        if len(targets) == 0 {
                return nil
        }
        bin := deepProbeBin()
        if bin == "" {
                return goFallbackProbe(targets, time.Duration(timeoutMs)*time.Millisecond)
        }
        var inbuf bytes.Buffer
        for _, t := range targets {
                rounds := t.Rounds
                if rounds < 1 {
                        rounds = 1
                }
                fmt.Fprintf(&inbuf, "%s %d %s %d\n", t.IP, orInt(t.Port, 443), t.SNI, rounds)
        }
        cmd := exec.Command(bin, itoa(timeoutMs))
        cmd.Stdin = &inbuf
        out, err := cmd.Output()
        if err != nil && len(out) == 0 {
                return goFallbackProbe(targets, time.Duration(timeoutMs)*time.Millisecond)
        }
        var results []ProbeResult
        for _, line := range strings.Split(string(out), "\n") {
                f := strings.Fields(line)
                if len(f) < 5 {
                        continue
                }
                tcpMs, _ := strconv.ParseFloat(f[2], 64)
                tlsMs, _ := strconv.ParseFloat(f[3], 64)
                results = append(results, ProbeResult{
                        Target: f[0], IP: f[0], OK: f[1] == "1",
                        TCPMs: tcpMs, TLSMs: tlsMs,
                        SNIOk: f[4] == "hello", SNIStat: f[4],
                })
        }
        if len(results) == 0 {
                return goFallbackProbe(targets, time.Duration(timeoutMs)*time.Millisecond)
        }
        return results
}

func orInt(v, def int) int {
        if v == 0 {
                return def
        }
        return v
}

// goFallbackProbe: pure-Go TCP connect probe (used when the Rust binary is absent).
func goFallbackProbe(targets []ProbeTarget, timeout time.Duration) []ProbeResult {
        type job struct {
                idx int
                t   ProbeTarget
        }
        jobs := make(chan job)
        results := make([]ProbeResult, len(targets))
        var wg sync.WaitGroup
        workers := 32
        if len(targets) < workers {
                workers = len(targets)
        }
        if workers == 0 {
                return results
        }
        for w := 0; w < workers; w++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for j := range jobs {
                                best := -1.0
                                rounds := j.t.Rounds
                                if rounds < 1 {
                                        rounds = 1
                                }
                                if rounds > 3 {
                                        rounds = 3
                                }
                                for i := 0; i < rounds; i++ {
                                        t0 := time.Now()
                                        conn, err := net.DialTimeout("tcp", net.JoinHostPort(j.t.IP, itoa(j.t.Port)), timeout)
                                        if err == nil {
                                                ms := float64(time.Since(t0).Microseconds()) / 1000.0
                                                conn.Close()
                                                if best < 0 || ms < best {
                                                        best = ms
                                                }
                                        }
                                }
                                results[j.idx] = ProbeResult{Target: j.t.IP, IP: j.t.IP, OK: best >= 0, TCPMs: round1max(best)}
                        }
                }()
        }
        for i, t := range targets {
                jobs <- job{i, t}
        }
        close(jobs)
        wg.Wait()
        return results
}

func round1max(v float64) float64 {
        if v < 0 {
                return 0
        }
        return round1(v)
}

// ─────────── bunny CDN edge discovery (Lucity's own bunny.net-fronted domain) ───────────

type bunnyCache struct {
        mu     sync.Mutex
        listT  time.Time
        ips    []string
        verT   time.Time
        dom    string
        ok     []string
        geoT   time.Time
        geo    map[string]map[string]string
}

var bunny = &bunnyCache{}

func (b *bunnyCache) ipList() []string {
        b.mu.Lock()
        defer b.mu.Unlock()
        if len(b.ips) > 0 && time.Since(b.listT) < 5*time.Minute {
                return b.ips
        }
        c := http.Client{Timeout: 8 * time.Second}
        resp, err := c.Get("https://api.bunny.net/system/edgeserverlist")
        if err != nil {
                return b.ips
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
        var raw []string
        if json.Unmarshal(body, &raw) == nil {
                var clean []string
                for _, ip := range raw {
                        if isValidScanTarget(ip) {
                                clean = append(clean, ip)
                        }
                }
                if len(clean) > 600 {
                        clean = clean[:600]
                }
                if len(clean) > 0 {
                        b.ips = clean
                        b.listT = time.Now()
                }
        }
        return b.ips
}

func isValidScanTarget(t string) bool {
        t = strings.TrimSpace(t)
        if t == "" || len(t) > 253 {
                return false
        }
        low := strings.ToLower(t)
        if strings.HasSuffix(low, ".internal") || strings.HasSuffix(low, ".local") || strings.HasSuffix(low, ".svc") || strings.HasSuffix(low, ".svc.") {
                return false
        }
        if isIPLiteral(t) {
                ip := net.ParseIP(strings.Trim(t, "[]"))
                if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
                        return false
                }
                return true
        }
        return hostRe.MatchString(t)
}

func (b *bunnyCache) geoBatch(ips []string) map[string]map[string]string {
        b.mu.Lock()
        defer b.mu.Unlock()
        if len(b.geo) > 0 && time.Since(b.geoT) < 6*time.Hour {
                return b.geo
        }
        geo := map[string]map[string]string{}
        c := http.Client{Timeout: 12 * time.Second}
        for i := 0; i < len(ips); i += 100 {
                chunk := ips[i:]
                if len(chunk) > 100 {
                        chunk = chunk[:100]
                }
                body, _ := json.Marshal(chunk)
                resp, err := c.Post("http://ip-api.com/batch?fields=status,query,countryCode,city",
                        "application/json", bytes.NewReader(body))
                if err != nil {
                        continue
                }
                rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
                resp.Body.Close()
                var rows []struct {
                        Status      string `json:"status"`
                        Query       string `json:"query"`
                        CountryCode string `json:"countryCode"`
                        City        string `json:"city"`
                }
                if json.Unmarshal(rb, &rows) == nil {
                        for _, r := range rows {
                                if r.Status == "success" {
                                        geo[r.Query] = map[string]string{"cc": r.CountryCode, "city": r.City}
                                }
                        }
                }
        }
        if len(geo) > 0 {
                b.geo = geo
                b.geoT = time.Now()
        }
        return geo
}

// verifyEdge does a full TLS handshake (chain + hostname) + one HTTP request.
func verifyEdge(ip, domain string, timeout time.Duration) bool {
        d := net.Dialer{Timeout: timeout}
        raw, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
        if err != nil {
                return false
        }
        tlsConn := tls.Client(raw, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
        if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
                raw.Close()
                return false
        }
        if err := tlsConn.Handshake(); err != nil {
                raw.Close()
                return false
        }
        defer tlsConn.Close()
        req := "GET / HTTP/1.1\r\nHost: " + domain + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        if _, err := tlsConn.Write([]byte(req)); err != nil {
                return false
        }
        buf := make([]byte, 128)
        n, _ := tlsConn.Read(buf)
        line := string(buf[:n])
        if !strings.HasPrefix(line, "HTTP/") {
                return false
        }
        parts := strings.SplitN(line, " ", 3)
        if len(parts) < 2 {
                return false
        }
        var code int
        fmt.Sscanf(parts[1], "%d", &code)
        return code >= 100 && code < 500
}

// bunnyEdgesFor: returns CDN edges that provably serve this domain, selected
// GEO-BALANCED (v3.3). The old pipeline ranked candidates by latency measured
// from THIS server (Hetzner DE) — so the "top 60" were all German edges and
// Iranian users never saw the Turkey/Caucasus/Iraq PoPs that ping best from
// Iran. Now every edge is geo-tagged first and a tiered per-country quota
// guarantees near-Iran regions dominate the shortlist; the browser then
// measures the real user-side RTT. Cached 6h per domain.
func bunnyEdgesFor(domain string) (edges []string, geo map[string]map[string]string, cached bool) {
        domain = strings.TrimSpace(strings.Split(domain, ":")[0])
        if domain == "" || isIPLiteral(domain) || !hostRe.MatchString(domain) {
                return nil, nil, false
        }
        bunny.mu.Lock()
        if len(bunny.ok) > 0 && bunny.dom == domain && time.Since(bunny.verT) < 6*time.Hour {
                edges := append([]string(nil), bunny.ok...)
                geo := bunny.geo
                bunny.mu.Unlock()
                return edges, geo, true
        }
        bunny.mu.Unlock()

        ips := bunny.ipList()
        if len(ips) == 0 {
                return nil, nil, false
        }

        // 1) geo-tag every bunny edge once (ip-api batch, 6h cache).
        geoAll := bunny.geoBatch(ips)

        // 2) tiered, per-country quota — near-Iran regions first.
        shortlist := pickEdgesByRegion(ips, geoAll, 130)
        if len(shortlist) == 0 {
                shortlist = ips
        }

        // 3) Rust prober: TCP + TLS ClientHello with our SNI (is the edge
        //    actually serving this hostname?).
        targets := make([]ProbeTarget, len(shortlist))
        for i, ip := range shortlist {
                targets[i] = ProbeTarget{IP: ip, Port: 443, SNI: domain}
        }
        res := runDeepProbe(targets, 2500)
        var alive []string
        for _, r := range res {
                if r.OK {
                        alive = append(alive, r.IP)
                }
        }
        if len(alive) > 100 {
                alive = alive[:100]
        }

        // 4) Full chain+hostname verification (Go crypto/tls) on the survivors.
        var verified []string
        sem := make(chan struct{}, 16)
        var wg sync.WaitGroup
        var mu sync.Mutex
        rank := map[string]int{} // keep tier order (near-Iran first) in the reply
        for i, ip := range alive {
                rank[ip] = i
        }
        for _, ip := range alive {
                wg.Add(1)
                go func(ip string) {
                        defer wg.Done()
                        sem <- struct{}{}
                        defer func() { <-sem }()
                        if verifyEdge(ip, domain, 4*time.Second) {
                                mu.Lock()
                                verified = append(verified, ip)
                                mu.Unlock()
                        }
                }(ip)
        }
        wg.Wait()
        sort2d := func(a []string) { // insertion-stable by pre-assigned rank
                for i := 1; i < len(a); i++ {
                        for j := i; j > 0 && rank[a[j-1]] > rank[a[j]]; j-- {
                                a[j-1], a[j] = a[j], a[j-1]
                        }
                }
        }
        sort2d(verified)

        geo = bunny.geoBatch(verified)
        bunny.mu.Lock()
        bunny.ok = verified
        bunny.dom = domain
        bunny.verT = time.Now()
        bunny.mu.Unlock()
        return verified, geo, false
}

// edgeRegionTiers: country → max edges, nearest-to-Iran first.
var edgeRegionTiers = []map[string]int{
        {"TR": 14, "AZ": 12, "GE": 12, "AM": 10, "IQ": 10, "AE": 10, "RO": 12, "BG": 10},                                        // tier 1 — Iran's neighbourhood
        {"QA": 6, "BH": 6, "OM": 6, "KW": 6, "SA": 6, "GR": 8, "CY": 6, "RS": 6, "MK": 4, "AL": 4, "BA": 4, "MD": 6, "UA": 6}, // tier 2
        {"HU": 5, "AT": 5, "SK": 5, "SI": 5, "HR": 5, "CZ": 5, "PL": 6, "DE": 10, "NL": 6, "CH": 5, "IT": 5, "FR": 4},          // tier 3
        {"SE": 3, "NO": 3, "DK": 3, "FI": 3, "LT": 3, "LV": 3, "EE": 3, "BE": 3, "LU": 2, "GB": 3, "IE": 2, "ES": 3, "PT": 2}, // tier 4 — fallback breadth
}

// pickEdgesByRegion walks the tiers in order, taking up to perCC edges from
// each country until total is filled (unknown-geo edges are skipped).
func pickEdgesByRegion(ips []string, geo map[string]map[string]string, total int) []string {
        if len(geo) == 0 || total <= 0 {
                return nil
        }
        seen := make(map[string]bool, len(ips))
        var out []string
        budget := total
        for _, tier := range edgeRegionTiers {
                used := map[string]int{}
                for _, ip := range ips {
                        if budget <= 0 {
                                return out
                        }
                        if seen[ip] {
                                continue
                        }
                        g, ok := geo[ip]
                        if !ok {
                                continue
                        }
                        cc := g["cc"]
                        cap, has := tier[cc]
                        if !has || used[cc] >= cap {
                                continue
                        }
                        seen[ip] = true
                        used[cc]++
                        out = append(out, ip)
                        budget--
                }
        }
        return out
}

// ─────────── client-side ISP detection (/panel/api/whoami) ───────────

type whoamiCacheEntry struct {
        op      string
        label   string
        cc      string
        city    string
        lat, lon float64
        expires time.Time
}

var (
        whoamiMu    sync.Mutex
        whoamiCache = map[string]*whoamiCacheEntry{}
)

var operatorASNPatterns = []struct {
        key, match string
}{
        {"irancell", "irancell"},
        {"mci", "mobile communication company"},
        {"mci", "mci"},
        {"rightel", "rightel"},
        {"shatel", "shatel"},
        {"mobinnet", "mobinnet"},
        {"mobinnet", "mobin"},
        {"parsonline", "pars online"},
        {"parsonline", "parsonline"},
        {"asiatek", "asiatech"},
        {"asiatek", "asia tech"},
        {"tci", "telecommunication infrastructure"},
        {"tci", "tci"},
        {"mokhaberat", "mokhaberat"},
}

func lookupWhoami(ip string) *whoamiCacheEntry {
        whoamiMu.Lock()
        if e, ok := whoamiCache[ip]; ok && time.Now().Before(e.expires) {
                whoamiMu.Unlock()
                return e
        }
        whoamiMu.Unlock()

        c := http.Client{Timeout: 5 * time.Second}
        url := "http://ip-api.com/json/" + ip + "?fields=status,query,countryCode,city,lat,lon,as,isp"
        resp, err := c.Get(url)
        if err != nil {
                return nil
        }
        defer resp.Body.Close()
        b, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
        var d struct {
                Status      string  `json:"status"`
                Query       string  `json:"query"`
                CountryCode string  `json:"countryCode"`
                City        string  `json:"city"`
                Lat         float64 `json:"lat"`
                Lon         float64 `json:"lon"`
                AS          string  `json:"as"`
                ISP         string  `json:"isp"`
        }
        if json.Unmarshal(b, &d) != nil || d.Status != "success" {
                return nil
        }
        e := &whoamiCacheEntry{op: "auto", label: "خودکار", cc: d.CountryCode, city: d.City,
                lat: d.Lat, lon: d.Lon, expires: time.Now().Add(time.Hour)}
        as := strings.ToLower(d.AS + " " + d.ISP)
        for _, p := range operatorASNPatterns {
                if strings.Contains(as, p.match) {
                        e.op = p.key
                        if prof, ok := operatorProfiles[p.key]; ok {
                                e.label = prof.Label
                        }
                        break
                }
        }
        whoamiMu.Lock()
        whoamiCache[ip] = e
        whoamiMu.Unlock()
        return e
}
