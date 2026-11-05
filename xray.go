package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────── xray core: locate binary, build config, supervise, stats ───────────

const apiPort = 10085

var (
	xrayMu       sync.Mutex
	xrayCmd      *exec.Cmd
	xrayPath     string
	xrayRestarts int
	xraySince    time.Time
	xrayActive   atomic.Value // map[string]bool of active client ids
	xrayLogMu    sync.Mutex
	xrayAlive    atomic.Bool
	statsReadMu  sync.Mutex
)

const xrayConf = "/tmp/xray.json"
const xrayLog = "/tmp/xray.log"

func findXray() string {
	candidates := []string{
		filepath.Join(appDir(), "xray"),
		filepath.Join(appDir(), "bin", "xray"),
		"/opt/deep-network/xray",
		"/usr/local/bin/xray",
		"/usr/bin/xray",
		filepath.Join(dataDir(), "bin", "xray"),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if m := st.Mode(); m&0o111 != 0 {
				return p
			}
		}
	}
	if p, err := exec.LookPath("xray"); err == nil {
		return p
	}
	return ""
}

// ensureXray locates or downloads the Xray core.
func ensureXray() string {
	if xrayPath != "" {
		return xrayPath
	}
	if p := findXray(); p != "" {
		xrayPath = p
		return p
	}
	dest := filepath.Join(dataDir(), "xray")
	if st, err := os.Stat(dest); err == nil && st.Mode()&0o111 != 0 {
		xrayPath = dest
		return dest
	}
	url := envStr("XRAY_DOWNLOAD_URL", "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		dest = "/tmp/bin/xray"
		_ = os.MkdirAll("/tmp/bin", 0o755)
	}
	logf("xray not found — downloading %s", url)
	if err := downloadUnzip(url, dest, "xray"); err != nil {
		logf("WARNING: could not download xray (%v); Reality stays disabled", err)
		return ""
	}
	_ = os.Chmod(dest, 0o755)
	xrayPath = dest
	logf("xray installed at %s", dest)
	return dest
}

func xhttpPath() string  { return normPath(osGetenv("XHTTP_PATH"), "/dn") }
func grpcService() string { return envStr("GRPC_SERVICE", "dn") }

// buildXrayConfig assembles the Xray server config:
// three VLESS-Reality inbounds (Vision / XHTTP / gRPC) on the public IP,
// speed-tuned (BBR sockopts, 1MB buffers, fast handshakes).
func buildXrayConfig() map[string]any {
	stateMu.RLock()
	clients := activeClientsLocked()
	stateMu.RUnlock()
	ports := effectivePorts()
	snis := effectiveSNIs()

	active := map[string]bool{}
	for _, c := range clients {
		active[c.ID] = true
	}
	xrayActive.Store(active)

	var users []map[string]any
	for _, c := range clients {
		users = append(users, map[string]any{"id": c.ID, "email": c.ID, "flow": "xtls-rprx-vision"})
	}
	var usersPlain []map[string]any
	for _, c := range clients {
		usersPlain = append(usersPlain, map[string]any{"id": c.ID, "email": c.ID})
	}

	sniff := map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}
	speedSock := map[string]any{
		"tcpNoDelay": true, "tcpKeepAliveIdle": 150, "tcpKeepAliveInterval": 15,
		"tcpcongestion": "bbr",
	}

	reality := func(sni string) map[string]any {
		return map[string]any{
			"show": false, "dest": sni + ":443", "xver": 0, "serverNames": []string{sni},
			"privateKey": realityPriv, "shortIds": []string{realitySID},
		}
	}

	var inbounds []map[string]any
	if realityPriv != "" {
		// 1) Vision — fastest (zero-copy XTLS)
		inbounds = append(inbounds, map[string]any{
			"tag": "vless-vision", "listen": "0.0.0.0", "port": ports.Vision, "protocol": "vless",
			"settings": map[string]any{"clients": users, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": reality(snis.Vision),
				"sockopt":         speedSock,
			},
			"sniffing": sniff,
		})
		// 2) XHTTP — packet-up, DPI-robust
		inbounds = append(inbounds, map[string]any{
			"tag": "vless-xhttp", "listen": "0.0.0.0", "port": ports.XHTTP, "protocol": "vless",
			"settings": map[string]any{"clients": usersPlain, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "reality",
				"xhttpSettings":   map[string]any{"path": xhttpPath(), "mode": "auto"},
				"realitySettings": reality(snis.XHTTP),
				"sockopt":         speedSock,
			},
			"sniffing": sniff,
		})
		// 3) gRPC — h2 multiplexed stream
		inbounds = append(inbounds, map[string]any{
			"tag": "vless-grpc", "listen": "0.0.0.0", "port": ports.GRPC, "protocol": "vless",
			"settings": map[string]any{"clients": usersPlain, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "grpc", "security": "reality",
				"grpcSettings":    map[string]any{"serviceName": grpcService()},
				"realitySettings": reality(snis.GRPC),
				"sockopt":         speedSock,
			},
			"sniffing": sniff,
		})
	}
	inbounds = append(inbounds, map[string]any{"tag": "api", "listen": "127.0.0.1", "port": apiPort,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}})

	privateNets := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

	return map[string]any{
		"log":   map[string]any{"loglevel": "warning"},
		"stats": map[string]any{},
		"api":   map[string]any{"tag": "api", "services": []string{"StatsService"}},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true,
			"handshake": 4, "connIdle": 600, "bufferSize": 1024}}},
		"dns": map[string]any{
			"servers": []string{"https+local://1.1.1.1/dns-query", "localhost"}, "queryStrategy": "UseIPv4"},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{"tag": "direct", "protocol": "freedom", "settings": map[string]any{
				"domainStrategy": "UseIPv4",
				"sockopt": map[string]any{"tcpNoDelay": true, "tcpKeepAliveIdle": 150,
					"tcpKeepAliveInterval": 15, "tcpFastOpen": true, "tcpcongestion": "bbr"}}},
			{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []map[string]any{
			{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			{"type": "field", "ip": privateNets, "outboundTag": "block"},
		}},
	}
}

func spawnXrayLocked() {
	conf := buildXrayConfig()
	writeJSON(xrayConf, conf)
	xrayLogMu.Lock()
	defer xrayLogMu.Unlock()
	if st, err := os.Stat(xrayLog); err == nil && st.Size() > 512*1024 {
		os.Remove(xrayLog)
	}
	lf, err := os.OpenFile(xrayLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logf("cannot open xray log: %v", err)
		return
	}
	bin := ensureXray()
	if bin == "" {
		logf("cannot start xray: binary missing")
		return
	}
	cmd := exec.Command(bin, "run", "-c", xrayConf)
	cmd.Stdout = nil
	cmd.Stderr = lf
	if err := cmd.Start(); err != nil {
		logf("cannot start xray: %v", err)
		lf.Close()
		return
	}
	xrayCmd = cmd
	xraySince = time.Now()
	xrayRestarts++
	xrayAlive.Store(true)
	go func() { _ = cmd.Wait(); xrayAlive.Store(false); lf.Close() }()
}

func restartXray() {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	restartXrayLocked()
}

func restartXrayLocked() {
	if xrayCmd != nil && xrayCmd.Process != nil {
		collectUsage()
		_ = xrayCmd.Process.Signal(termSignal())
		time.Sleep(600 * time.Millisecond)
		_ = xrayCmd.Process.Kill()
	}
	spawnXrayLocked()
}

func xrayRunning() bool { return xrayAlive.Load() }

// xrayStats queries the stats API: {email: {up, down}}; counters reset on read.
func xrayStats() map[string][2]int64 {
	return xrayStatsReset(true)
}

func xrayStatsPeek() map[string][2]int64 {
	return xrayStatsReset(false)
}

func xrayStatsArgs(reset bool) []string {
	args := []string{"api", "statsquery", "--server=127.0.0.1:" + strconv.Itoa(apiPort), "-pattern", "user>>>"}
	if reset {
		args = append(args, "-reset")
	}
	return args
}

func xrayStatsReset(reset bool) map[string][2]int64 {
	bin := ensureXray()
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, xrayStatsArgs(reset)...).Output()
	if err != nil {
		return nil
	}
	var data struct {
		Stat []struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if jsonUnmarshal(out, &data) != nil {
		return nil
	}
	res := map[string][2]int64{}
	for _, st := range data.Stat {
		p := strings.Split(st.Name, ">>>")
		if len(p) == 4 && p[0] == "user" {
			v := res[p[1]]
			if p[3] == "uplink" {
				v[0] += st.Value
			} else {
				v[1] += st.Value
			}
			res[p[1]] = v
		}
	}
	return res
}

func collectUsage() {
	if !xrayRunning() {
		return
	}
	statsReadMu.Lock()
	stats := xrayStats()
	statsReadMu.Unlock()
	if len(stats) == 0 {
		return
	}
	applyUserStats(stats, time.Now())
	stateMu.Lock()
	saveStateLocked()
	stateMu.Unlock()
}

func syncXray() {
	stateMu.RLock()
	nowActive := map[string]bool{}
	for _, c := range activeClientsLocked() {
		nowActive[c.ID] = true
	}
	stateMu.RUnlock()
	prev, _ := xrayActive.Load().(map[string]bool)
	if !mapsEqual(nowActive, prev) {
		restartXray()
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func logTail(n int) []string {
	xrayLogMu.Lock()
	defer xrayLogMu.Unlock()
	f, err := os.Open(xrayLog)
	if err != nil {
		return nil
	}
	defer f.Close()
	const window = 256 * 1024
	st, _ := f.Stat()
	off := int64(0)
	if st.Size() > window {
		off = st.Size() - window
	}
	buf := make([]byte, st.Size()-off)
	_, _ = f.ReadAt(buf, off)
	lines := strings.Split(strings.ReplaceAll(string(buf), "\r\n", "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	var out []string
	for _, l := range lines {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
