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

// ─────────── xray core: locate binary, build config, supervise process, stats ───────────

const apiPort = 10085

var builtinPorts = map[int]bool{}

func init() {
	for _, p := range []int{envInt("PORT", 8080), tcpAppPort(), apiPort, 10001, 10002, 10003, 10004, 10005, 10006} {
		builtinPorts[p] = true
	}
}

func tcpAppPort() int {
	return envInt("RAILWAY_TCP_APPLICATION_PORT", envInt("TCP_APP_PORT", 9000))
}

var (
	xrayMu       sync.Mutex
	xrayCmd      *exec.Cmd
	xrayPath     string
	xrayRestarts int
	xraySince    time.Time
	xrayActive   atomic.Value // map[string]bool of active client ids
	xrayLogMu    sync.Mutex
	xrayAlive    atomic.Bool
)

const xrayConf = "/tmp/xray.json"
const xrayLog = "/tmp/xray.log"

func findXray() string {
	candidates := []string{
		filepath.Join(appDir(), "bin", "xray"),
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

// ensureXray locates or downloads the Xray core (same fallback flow as the Python panel).
func ensureXray() string {
	if xrayPath != "" {
		return xrayPath
	}
	if p := findXray(); p != "" {
		xrayPath = p
		return p
	}
	dest := filepath.Join(dataDir(), "bin", "xray")
	if st, err := os.Stat(dest); err == nil && st.Mode()&0o111 != 0 {
		xrayPath = dest
		return dest
	}
	url := envStr("XRAY_DOWNLOAD_URL", "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		dest = "/tmp/bin/xray"
		_ = os.MkdirAll("/tmp/bin", 0o755)
	}
	logf("xray not found - downloading %s", url)
	if err := downloadUnzip(url, dest, "xray"); err != nil {
		logf("WARNING: could not download xray (%v); TCP/Reality will stay disabled", err)
		return ""
	}
	_ = os.Chmod(dest, 0o755)
	xrayPath = dest
	logf("xray installed at %s", dest)
	return dest
}

// buildXrayConfig assembles the Xray server config (ports & policy tuned like the Python panel).
func buildXrayConfig() map[string]any {
	stateMu.RLock()
	clients := activeClientsLocked()
	sni := state.RealitySNI
	var customs []*Inbound
	for _, ib := range state.Inbounds {
		cp := *ib
		customs = append(customs, &cp)
	}
	stateMu.RUnlock()

	active := map[string]bool{}
	for _, c := range clients {
		active[c.ID] = true
	}
	xrayActive.Store(active)

	sniff := map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true}

	idsFor := func(key string) []map[string]any {
		var out []map[string]any
		for _, c := range clients {
			if userProtocolsLocked(c)[key] {
				out = append(out, map[string]any{"id": c.ID, "email": c.ID})
			}
		}
		return out
	}
	trojanFor := func(key string) []map[string]any {
		var out []map[string]any
		for _, c := range clients {
			if userProtocolsLocked(c)[key] {
				out = append(out, map[string]any{"password": c.ID, "email": c.ID})
			}
		}
		return out
	}
	wsStream := func(p string) map[string]any {
		return map[string]any{"network": "ws", "wsSettings": map[string]any{
			"path": p, "maxEarlyData": 2048, "earlyDataHeaderName": "Sec-WebSocket-Protocol"}}
	}
	local := func(tag string, port int, proto string, settings, stream map[string]any) map[string]any {
		return map[string]any{"tag": tag, "listen": "127.0.0.1", "port": port, "protocol": proto,
			"settings": settings, "streamSettings": stream, "sniffing": sniff}
	}

	var inbounds []map[string]any
	if protoEnabled("vless-xhttp") {
		inbounds = append(inbounds, local("vless-xhttp", 10002, "vless",
			map[string]any{"clients": idsFor("vless-xhttp"), "decryption": "none"},
			map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": xhttpPath(), "mode": "auto"}}))
	}
	if protoEnabled("vless-hu") {
		inbounds = append(inbounds, local("vless-hu", 10006, "vless",
			map[string]any{"clients": idsFor("vless-hu"), "decryption": "none"},
			map[string]any{"network": "httpupgrade", "httpupgradeSettings": map[string]any{"path": huPath()}}))
	}
	if protoEnabled("vless-ws") {
		inbounds = append(inbounds, local("vless-ws", 10001, "vless",
			map[string]any{"clients": idsFor("vless-ws"), "decryption": "none"}, wsStream(wsPath())))
	}
	if protoEnabled("vmess-ws") {
		inbounds = append(inbounds, local("vmess-ws", 10004, "vmess",
			map[string]any{"clients": idsFor("vmess-ws")}, wsStream(vmessPath())))
	}
	if protoEnabled("trojan-ws") {
		inbounds = append(inbounds, local("trojan-ws", 10005, "trojan",
			map[string]any{"clients": trojanFor("trojan-ws")}, wsStream(trojanPath())))
	}
	if realityPub != "" && protoEnabled("vless-reality") {
		var users []map[string]any
		for _, u := range idsFor("vless-reality") {
			u["flow"] = "xtls-rprx-vision"
			users = append(users, u)
		}
		inbounds = append(inbounds, map[string]any{
			"tag": "vless-reality", "listen": "0.0.0.0", "port": tcpAppPort(), "protocol": "vless",
			"settings": map[string]any{"clients": users, "decryption": "none"},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"show": false, "dest": sni + ":443", "xver": 0, "serverNames": []string{sni},
					"privateKey": realityPriv, "shortIds": []string{realitySID},
				},
			},
			"sniffing": sniff,
		})
	}
	for _, ib := range customs {
		if ib.Security == "reality" && realityPriv == "" {
			continue
		}
		var users []map[string]any
		if ib.Protocol == "trojan" {
			for _, c := range clients {
				if userProtocolsLocked(c)[ib.Protocol] || len(c.Protocols) == 0 {
					users = append(users, map[string]any{"password": c.ID, "email": c.ID})
				}
			}
		} else {
			for _, c := range clients {
				users = append(users, map[string]any{"id": c.ID, "email": c.ID})
			}
		}
		settings := map[string]any{"clients": users}
		if ib.Protocol == "vless" {
			settings["decryption"] = "none"
		}
		stream := map[string]any{"network": ib.Network}
		switch ib.Network {
		case "ws":
			stream["wsSettings"] = map[string]any{"path": ib.Path, "maxEarlyData": 2048, "earlyDataHeaderName": "Sec-WebSocket-Protocol"}
		case "xhttp":
			stream["xhttpSettings"] = map[string]any{"path": ib.Path, "mode": "auto"}
		case "httpupgrade":
			stream["httpupgradeSettings"] = map[string]any{"path": ib.Path}
		case "grpc":
			stream["grpcSettings"] = map[string]any{"serviceName": strings.TrimPrefix(ib.Path, "/")}
		}
		listen, port := "127.0.0.1", ib.LPort
		if ib.Security == "reality" {
			stream["security"] = "reality"
			stream["realitySettings"] = map[string]any{
				"show": false, "dest": ib.SNI + ":443", "xver": 0, "serverNames": []string{ib.SNI},
				"privateKey": realityPriv, "shortIds": []string{realitySID}}
			listen, port = "0.0.0.0", ib.Port
		}
		inbounds = append(inbounds, map[string]any{"tag": ib.Tag, "listen": listen, "port": port,
			"protocol": ib.Protocol, "settings": settings, "streamSettings": stream, "sniffing": sniff})
	}
	inbounds = append(inbounds, map[string]any{"tag": "api", "listen": "127.0.0.1", "port": apiPort,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}})

	privateNets := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

	return map[string]any{
		"log":     map[string]any{"loglevel": "warning"},
		"stats":   map[string]any{},
		"api":     map[string]any{"tag": "api", "services": []string{"StatsService"}},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{
			"statsUserUplink": true, "statsUserDownlink": true,
			"handshake": 4, "connIdle": envInt("XRAY_IDLE", 600), "bufferSize": envInt("XRAY_BUFFER", 1024)}}},
		"dns": map[string]any{
			"servers": []string{"https+local://1.1.1.1/dns-query", "localhost"}, "queryStrategy": "UseIPv4"},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{"tag": "direct", "protocol": "freedom", "settings": map[string]any{
				"domainStrategy": "UseIPv4",
				"sockopt":        map[string]any{"tcpNoDelay": true, "tcpKeepAliveIdle": 150, "tcpKeepAliveInterval": 15, "tcpFastOpen": true}}},
			{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"domainStrategy": "IPIfNonMatch", "rules": []map[string]any{
			{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
			{"type": "field", "domain": []string{"domain:railway.internal", "domain:svc.cluster.local", "domain:localhost"}, "outboundTag": "block"},
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
		// the Start()-watcher goroutine reaps the process; give it a moment
		// to release the inbound ports before spawning the replacement.
		time.Sleep(600 * time.Millisecond)
		_ = xrayCmd.Process.Kill()
	}
	spawnXrayLocked()
}

func xrayRunning() bool { return xrayAlive.Load() }

// xrayStats queries the stats API: {email: {up, down}}; counters reset on read.
func xrayStats() map[string][2]int64 {
	bin := ensureXray()
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "api", "statsquery",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort), "-pattern", "user>>>", "-reset").Output()
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
	stats := xrayStats()
	if len(stats) == 0 {
		return
	}
	stateMu.Lock()
	for _, c := range state.Clients {
		if s, ok := stats[c.ID]; ok {
			c.Up += s[0]
			c.Down += s[1]
		}
	}
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
