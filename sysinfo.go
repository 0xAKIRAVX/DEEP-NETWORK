package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─────────── real system metrics (cgroup-aware, 1s sampling) ───────────

var (
	startTime = time.Now()
	cores     = quotaCores() // container CPU quota (not the host's 8+ cores)
)

// quotaCores returns the cgroup v2 cpu.max quota rounded up to whole cores,
// falling back to the visible host core count when no quota is set. On Lucity
// (Kubernetes) the container usually gets a small fraction of the node —
// reporting the node's core count was misleading.
func quotaCores() int {
	mx := strings.Fields(readFileTrim("/sys/fs/cgroup/cpu.max"))
	if len(mx) == 2 {
		if q, e1 := strconv.ParseInt(mx[0], 10, 64); e1 == nil {
			if p, e2 := strconv.ParseInt(mx[1], 10, 64); e2 == nil && p > 0 && q > 0 {
				n := int((float64(q)/float64(p))*100+99) / 100
				if n < 1 {
					n = 1
				}
				return n
			}
		}
	}
	return runtime.NumCPU()
}

type SamplePoint struct {
	T   int64   `json:"t"`
	CPU float64 `json:"cpu"`
	Mem float64 `json:"mem"`
	RX  float64 `json:"rx"`
	TX  float64 `json:"tx"`
}

type Sampler struct {
	mu     sync.RWMutex
	hist   []SamplePoint
	latest SamplePoint
	memU   int
	memT   int
	rxTot  int64
	txTot  int64
	prev   *struct {
		t   time.Time
		cpu float64
		rx  int64
		tx  int64
	}
}

var sampler = &Sampler{}

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func kvFile(p string) map[string]int64 {
	d := map[string]int64{}
	for _, line := range strings.Split(readFileTrim(p), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			if v, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				d[parts[0]] = v
			}
		}
	}
	return d
}

func memInfo() (used, total int, percent float64) {
	// NOTE(v3.4 bug fix): /proc/meminfo lines look like "MemTotal:  264013812 kB"
	// — strings.Fields yields THREE fields because of the colon ("MemTotal:").
	// The old len(f)==2 check never matched, so hostTotal stayed 0 → the panel
	// reported "0 MB total / 0%" RAM forever (the "fake RAM" bug).
	memLine := func(key string) int64 {
		for _, line := range strings.Split(readFileTrim("/proc/meminfo"), "\n") {
			if strings.HasPrefix(line, key) {
				f := strings.Fields(line)
				if len(f) >= 2 {
					if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
						return v * 1024
					}
				}
			}
		}
		return 0
	}
	hostTotal := memLine("MemTotal")
	curS := readFileTrim("/sys/fs/cgroup/memory.current")
	limS := readFileTrim("/sys/fs/cgroup/memory.max")
	inactive := kvFile("/sys/fs/cgroup/memory.stat")["inactive_file"]
	if curS == "" { // cgroup v1
		curS = readFileTrim("/sys/fs/cgroup/memory/memory.usage_in_bytes")
		limS = readFileTrim("/sys/fs/cgroup/memory/memory.limit_in_bytes")
		inactive = kvFile("/sys/fs/cgroup/memory/memory.stat")["total_inactive_file"]
	}
	var cur int64
	if v, err := strconv.ParseInt(curS, 10, 64); err == nil {
		cur = v
	}
	lim := int64(0)
	if v, err := strconv.ParseInt(limS, 10, 64); err == nil {
		lim = v
	}
	if cur > 0 {
		usedB := cur - inactive
		if usedB < 0 {
			usedB = 0
		}
		totalB := hostTotal
		if lim > 0 && lim < hostTotal {
			totalB = lim
		}
		used, total = int(usedB>>20), int(totalB>>20)
	} else {
		avail := memLine("MemAvailable")
		total = int(hostTotal >> 20)
		used = int((hostTotal - avail) >> 20)
	}
	if total > 0 {
		percent = float64(used) / float64(total) * 100
	}
	if percent > 100 {
		percent = 100
	}
	return
}

// diskRoot points at the user's persistent volume (/data on Lucity) —
// statfs("/") used to report the whole node disk (137GB), which is not what
// the user actually has. Falls back to / when the data dir is unavailable.
var diskRoot = dataDir()

func diskInfo() (used, total float64, percent float64) {
	st, err := statfsPath(diskRoot)
	if err != nil {
		st, err = statfsPath("/")
		if err != nil {
			return 0, 0, 0
		}
	}
	total = float64(st.Blocks*uint64(st.Bsize)) / (1 << 30)
	used = float64((st.Blocks-st.Bfree)*uint64(st.Bsize)) / (1 << 30)
	if total > 0 {
		percent = used / total * 100
	}
	return
}

func netBytes() (rx, tx int64) {
	for _, line := range strings.Split(readFileTrim("/proc/net/dev"), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) >= 9 {
			r, _ := strconv.ParseInt(f[0], 10, 64)
			t, _ := strconv.ParseInt(f[8], 10, 64)
			rx += r
			tx += t
		}
	}
	return
}

func osInfo() string {
	txt := readFileTrim("/etc/os-release")
	for _, line := range strings.Split(txt, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			v = strings.Trim(v, `"`)
			return v
		}
	}
	if k := readFileTrim("/proc/sys/kernel/osrelease"); k != "" {
		return "Linux " + k
	}
	return "Linux"
}

func cpuModel() string {
	for _, line := range strings.Split(readFileTrim("/proc/cpuinfo"), "\n") {
		if strings.HasPrefix(strings.ToLower(line), "model name") && strings.Contains(line, ":") {
			return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}
	}
	return ""
}

func cpuCounter() (float64, float64) {
	if usage, ok := kvFile("/sys/fs/cgroup/cpu.stat")["usage_usec"]; ok {
		c := float64(cores)
		mx := strings.Fields(readFileTrim("/sys/fs/cgroup/cpu.max"))
		if len(mx) == 2 {
			q, e1 := strconv.ParseInt(mx[0], 10, 64)
			p, e2 := strconv.ParseInt(mx[1], 10, 64)
			if e1 == nil && e2 == nil && p > 0 && q > 0 {
				c = float64(q) / float64(p)
			}
		}
		return float64(usage) / 1e6, c
	}
	first := "cpu 0 0 0 0"
	for _, l := range strings.Split(readFileTrim("/proc/stat"), "\n") {
		if strings.HasPrefix(l, "cpu ") {
			first = l
			break
		}
	}
	var vals []int64
	for _, f := range strings.Fields(strings.TrimPrefix(first, "cpu")) {
		if v, err := strconv.ParseInt(f, 10, 64); err == nil {
			vals = append(vals, v)
		}
	}
	busy := int64(0)
	for i, v := range vals {
		if i != 3 && i != 4 {
			busy += v
		}
	}
	return float64(busy) / 100.0, float64(cores)
}

func (s *Sampler) sample() {
	now := time.Now()
	cpuC, c := cpuCounter()
	rx, tx := netBytes()
	cpu, rxs, txs := 0.0, 0.0, 0.0
	if s.prev != nil {
		dt := now.Sub(s.prev.t).Seconds()
		if dt < 0.001 {
			dt = 0.001
		}
		cpu = (cpuC - s.prev.cpu) / dt / max64(c, 0.01) * 100
		if cpu < 0 {
			cpu = 0
		}
		if cpu > 100 {
			cpu = 100
		}
		rxs = max64(float64(rx-s.prev.rx), 0) / dt
		txs = max64(float64(tx-s.prev.tx), 0) / dt
	}
	s.prev = &struct {
		t   time.Time
		cpu float64
		rx  int64
		tx  int64
	}{now, cpuC, rx, tx}
	mu, mt, mp := memInfo()
	s.mu.Lock()
	s.hist = append(s.hist, SamplePoint{T: now.Unix(), CPU: round1(cpu), Mem: round1(mp), RX: rxs, TX: txs})
	if len(s.hist) > 150 {
		s.hist = s.hist[len(s.hist)-150:]
	}
	s.latest = SamplePoint{T: now.Unix(), CPU: round1(cpu), Mem: round1(mp), RX: rxs, TX: txs}
	s.memU, s.memT, s.rxTot, s.txTot = mu, mt, rx, tx
	s.mu.Unlock()
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

func max64(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func samplerLoop() {
	for {
		sampler.sample()
		time.Sleep(time.Second)
	}
}

// ─────────── server geo (real public-IP location, cached 24h) ───────────

type Geo struct {
	IP      string  `json:"ip"`
	Country string  `json:"country"`
	CC      string  `json:"cc"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

var (
	geoMu   sync.Mutex
	geoVal  *Geo
	geoTime time.Time
)

func serverGeo() *Geo {
	geoMu.Lock()
	defer geoMu.Unlock()
	if geoVal != nil && time.Since(geoTime) < 24*time.Hour {
		return geoVal
	}
	c := http.Client{Timeout: 6 * time.Second}
	req, _ := http.NewRequest("GET", "http://ip-api.com/json?fields=status,query,country,countryCode,city,lat,lon", nil)
	req.Header.Set("User-Agent", "DeepNetwork/"+Version)
	resp, err := c.Do(req)
	if err != nil {
		return geoVal
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	var d struct {
		Status      string  `json:"status"`
		Query       string  `json:"query"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
	}
	if json.Unmarshal(b, &d) == nil && d.Status == "success" && d.Lat != 0 {
		geoVal = &Geo{IP: d.Query, Country: d.Country, CC: d.CountryCode, City: d.City,
			Lat: d.Lat, Lon: d.Lon}
		geoTime = time.Now()
	}
	return geoVal
}

func trafficSnapshot() {
	day := time.Now().Unix() / 86400
	stateMu.Lock()
	defer stateMu.Unlock()
	var total int64
	for _, c := range state.Clients {
		total += c.Up + c.Down
	}
	snaps := state.TSnaps
	changed := false
	if len(snaps) > 0 && snaps[len(snaps)-1].D == day {
		if snaps[len(snaps)-1].T != total {
			snaps[len(snaps)-1].T = total
			changed = true
		}
	} else {
		snaps = append(snaps, TSnap{D: day, T: total})
		if len(snaps) > 40 {
			snaps = snaps[len(snaps)-40:]
		}
		changed = true
	}
	state.TSnaps = snaps
	if changed {
		saveStateLocked()
	}
}

func traffic30d() map[string]any {
	day := time.Now().Unix() / 86400
	stateMu.RLock()
	var total int64
	for _, c := range state.Clients {
		total += c.Up + c.Down
	}
	snaps := append([]TSnap(nil), state.TSnaps...)
	stateMu.RUnlock()
	ref := func(daysAgo int64) *TSnap {
		var best *TSnap
		for i := range snaps {
			age := day - snaps[i].D
			if daysAgo-1 <= age && age <= daysAgo+1 {
				if best == nil || age < day-best.D {
					best = &snaps[i]
				}
			}
		}
		return best
	}
	r30, r60 := ref(30), ref(60)
	var b30, b64v *int64
	if r30 != nil {
		v := total - r30.T
		if v < 0 {
			v = 0
		}
		b30 = &v
	}
	if r60 != nil {
		v := total - r60.T
		if v < 0 {
			v = 0
		}
		b64v = &v
	}
	out := map[string]any{"bytes": nil, "pct": nil}
	if b30 != nil {
		out["bytes"] = *b30
		if b64v != nil && *b64v > 0 {
			out["pct"] = int64((*b30 - *b64v) * 100 / *b64v)
		}
	}
	return out
}

func statsPayload() map[string]any {
	sampler.mu.RLock()
	latest := sampler.latest
	hist := append([]SamplePoint(nil), sampler.hist...)
	memU, memT := sampler.memU, sampler.memT
	rxT, txT := sampler.rxTot, sampler.txTot
	sampler.mu.RUnlock()
	diskU, diskT, diskP := diskInfo()
	// v3.6: "t" carries the REAL per-sample timestamps — the client chart
	// engine anchors each point to its true time (sampler jitter tolerant
	// + enables smooth 60fps time-scroll instead of index spacing).
	hm := map[string][]float64{"cpu": {}, "mem": {}, "rx": {}, "tx": {}, "t": {}}
	for _, p := range hist {
		hm["cpu"] = append(hm["cpu"], p.CPU)
		hm["mem"] = append(hm["mem"], p.Mem)
		hm["rx"] = append(hm["rx"], p.RX)
		hm["tx"] = append(hm["tx"], p.TX)
		hm["t"] = append(hm["t"], float64(p.T))
	}
	stateMu.RLock()
	var clients int64
	for _, c := range state.Clients {
		if clientStatus(c, time.Now()) == "active" {
			clients++
		}
	}
	stateMu.RUnlock()
	return map[string]any{
		"t": latest.T, "cpu": latest.CPU, "mem": latest.Mem, "rx": latest.RX, "tx": latest.TX,
		"mem_used": memU, "mem_total": memT, "rx_total": rxT, "tx_total": txT,
		"disk":   map[string]any{"used": diskU, "total": diskT, "percent": diskP},
		"uptime": int64(time.Since(startTime).Seconds()),
		"cores":  cores, "os": osInfo(), "cpu_model": cpuModel(),
		"version": Version, "traffic30": traffic30d(), "geo": serverGeo(),
		"online": onlineTunnels(), "clients": clients,
		"online_users": onlineCount(),
		"hist":         map[string][]float64{"cpu": hm["cpu"], "mem": hm["mem"], "rx": hm["rx"], "tx": hm["tx"], "t": hm["t"]},
		"interval":     1.0,
	}
}

func healthPayload() map[string]any {
	t0 := time.Now()
	if xrayRunning() {
		// v3.10 FIX: this used the destructive -reset read, so every health
		// probe silently discarded uncounted user traffic. Peek instead.
		statsReadMu.Lock()
		xrayStatsPeek()
		statsReadMu.Unlock()
	}
	lat := time.Since(t0).Milliseconds()
	return map[string]any{
		"ok": xrayRunning(), "xray": xrayRunning(), "go": true,
		"latency_ms": lat, "uptime": int64(time.Since(startTime).Seconds()),
		"version": Version, "restarts": xrayRestarts,
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}

func osGetenv(k string) string { return os.Getenv(k) }

func sortStrings(s []string) { sort.Strings(s) }

// ─────────── statfs (disk usage) ───────────

type statfsT = syscall.Statfs_t

func statfsRoot() (*statfsT, error) {
	return statfsPath("/")
}

func statfsPath(p string) (*statfsT, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
