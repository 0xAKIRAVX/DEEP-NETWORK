package main

// ─────────── v3.15: دکتر پنل / panel doctor ───────────
// The panel periodically proves its OWN configs end-to-end: for every enabled
// transport it builds the exact client config a user would import (same
// sniFor/linkSNI/path logic — including the SNI front), runs it as a REAL
// xray client process with a local SOCKS inbound, and fetches
// http://www.gstatic.com/generate_204 through the tunnel.
//
// This is the same "does it actually connect" test an admin would do by hand
// with a phone — automated, after every scan, and surfaced in the UI, so a
// broken transport is caught by the panel before any user reports it.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	doctorMu      sync.Mutex
	doctorRunning bool
)

// doctorTargets: transports the doctor rides (Reality is direct-TCP, no CDN).
var doctorKeys = []string{"vless-ws", "vless-xhttp", "vless-hu", "vmess-ws", "trojan-ws"}

// doctorClientConfig mirrors buildLinksAddr emission for one transport so the
// doctor tests exactly what users receive.
func doctorClientConfig(c *Client, key, addr, domain string, socksPort int) (map[string]any, error) {
	sniHost := sniFor(addr, domain)
	tlsName := linkSNI(sniHost)
	if tlsName == "" || isIPLiteral(tlsName) {
		return nil, fmt.Errorf("no TLS name for %s", key)
	}
	// v3.21.2: XHTTP rides the origin ingress, not the edge — bunny's h2
	// layer stalls its stream tails (see originFor). Same for the fetch
	// target below: the doctor now verifies REAL completion, and only
	// the direct path can prove XHTTP end-to-end.
	dialAddr := addr
	tls := map[string]any{"serverName": tlsName, "fingerprint": "chrome", "allowInsecure": false}
	stream := map[string]any{"network": "", "security": "tls", "tlsSettings": tls}
	switch key {
	case "vless-ws":
		stream["network"] = "ws"
		stream["wsSettings"] = map[string]any{"path": wsPath() + "?ed=2048",
			"headers": map[string]any{"Host": sniHost}}
		tls["alpn"] = []string{"http/1.1"}
	case "vless-hu":
		stream["network"] = "httpupgrade"
		stream["httpupgradeSettings"] = map[string]any{"path": huPath(), "host": sniHost}
		tls["alpn"] = []string{"http/1.1"}
	case "vless-xhttp":
		o := originFor(domain)
		if o.ip == "" {
			return nil, fmt.Errorf("origin unresolved for %s", domain)
		}
		dialAddr = o.ip
		stream["network"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{"path": xhttpPath(), "mode": "packet-up", "host": domain}
		tls["serverName"] = domain
		tls["alpn"] = []string{"h2", "http/1.1"}
	case "vmess-ws":
		stream["network"] = "ws"
		stream["wsSettings"] = map[string]any{"path": vmessPath() + "?ed=2048",
			"headers": map[string]any{"Host": sniHost}}
		tls["alpn"] = []string{"http/1.1"}
	case "trojan-ws":
		stream["network"] = "ws"
		stream["wsSettings"] = map[string]any{"path": trojanPath() + "?ed=2048",
			"headers": map[string]any{"Host": sniHost}}
		tls["alpn"] = []string{"http/1.1"}
	default:
		return nil, fmt.Errorf("unknown transport %s", key)
	}
	var outbound map[string]any
	switch key {
	case "vless-ws", "vless-hu", "vless-xhttp":
		outbound = map[string]any{"tag": "proxy", "protocol": "vless",
			"settings": map[string]any{"vnext": []map[string]any{{
				"address": dialAddr, "port": 443,
				"users": []map[string]any{{"id": c.ID, "encryption": "none"}}}}},
			"streamSettings": stream}
	case "vmess-ws":
		outbound = map[string]any{"tag": "proxy", "protocol": "vmess",
			"settings": map[string]any{"vnext": []map[string]any{{
				"address": addr, "port": 443,
				"users": []map[string]any{{"id": c.ID, "alterId": 0, "security": "auto"}}}}},
			"streamSettings": stream}
	case "trojan-ws":
		outbound = map[string]any{"tag": "proxy", "protocol": "trojan",
			"settings": map[string]any{"servers": []map[string]any{{
				"address": addr, "port": 443, "password": c.ID}}},
			"streamSettings": stream}
	}
	return map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []map[string]any{{"tag": "socks", "listen": "127.0.0.1", "port": socksPort,
			"protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []map[string]any{outbound},
	}, nil
}

// socksDial performs a minimal SOCKS5 CONNECT (greeting → CONNECT host:port).
func socksDial(port int, host string, dstPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks: no acceptable auth (code %d)", head[1])
	}
	hb := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	hb = append(hb, []byte(host)...)
	hb = append(hb, byte(dstPort>>8), byte(dstPort))
	if _, err := conn.Write(hb); err != nil {
		conn.Close()
		return nil, err
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(conn, rep); err != nil {
		conn.Close()
		return nil, err
	}
	if rep[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks: connect refused (code %d)", rep[1])
	}
	var skip int
	switch rep[3] {
	case 0x01:
		skip = 6
	case 0x03:
		ln := make([]byte, 1)
		if _, err := io.ReadFull(conn, ln); err != nil {
			conn.Close()
			return nil, err
		}
		skip = 1 + int(ln[0]) + 2
	case 0x04:
		skip = 18
	}
	if skip > 0 {
		if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// doctorOne runs a single transport probe and returns its verdict.
func doctorOne(c *Client, key, addr, domain string) DocRes {
	res := DocRes{Edge: addr}
	socksPort, err := freeLocalPort(21000, 29000)
	if err != nil {
		res.Err = "port: " + err.Error()
		return res
	}
	cfg, err := doctorClientConfig(c, key, addr, domain, socksPort)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	confPath := filepath.Join(os.TempDir(), fmt.Sprintf("dn-doc-%s.json", key))
	b, _ := json.Marshal(cfg)
	if os.WriteFile(confPath, b, 0o600) != nil {
		res.Err = "write conf"
		return res
	}
	defer os.Remove(confPath)
	bin := ensureXray()
	if bin == "" {
		res.Err = "xray binary missing"
		return res
	}
	cmd := exec.Command(bin, "run", "-c", confPath)
	if err := cmd.Start(); err != nil {
		res.Err = "spawn: " + err.Error()
		return res
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() {
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}()
	time.Sleep(900 * time.Millisecond)

	// v3.16: the client core can need a moment to bind its SOCKS port —
	// a single fast dial made the doctor flap on slower boots. Retry a few
	// times before declaring the transport broken.
	var conn net.Conn
	var derr error
	for try := 0; try < 4; try++ {
		conn, derr = socksDial(socksPort, domain, 443)
		if derr == nil {
			break
		}
		time.Sleep(700 * time.Millisecond)
	}
	if derr != nil {
		res.Err = "socks: " + derr.Error()
		return res
	}
	defer conn.Close()
	// v3.21.2: completion-based verdict. The old HEAD /generate_204 only
	// proved the tunnel could carry a header line — the 2026-10-25
	// incident (XHTTP through bunny's h2 layer) handshook fine while
	// every chunked page stalled at ~96% forever: "config pings but
	// nothing loads". The doctor now pulls a real CHUNKED payload (the
	// panel's own speedblob in chunked mode) through the exact user
	// tunnel and requires the FULL body plus clean EOF.
	tconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	_ = tconn.SetDeadline(time.Now().Add(25 * time.Second))
	if err := tconn.Handshake(); err != nil {
		res.Err = "tls: " + err.Error()
		return res
	}
	t0 := time.Now()
	req := "GET /panel/api/speedblob?n=96&chunked=1 HTTP/1.1\r\nHost: " + domain +
		"\r\nUser-Agent: dn-doctor\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := tconn.Write([]byte(req)); err != nil {
		res.Err = "http write: " + err.Error()
		return res
	}
	rdr := bufio.NewReader(tconn)
	line, err := rdr.ReadString('\n')
	if err != nil {
		res.Err = "http read: " + err.Error()
		return res
	}
	res.MS = time.Since(t0).Milliseconds()
	if !strings.Contains(line, " 200") {
		res.Err = "status: " + strings.TrimSpace(line)
		return res
	}
	for {
		h, err := rdr.ReadString('\n')
		if err != nil {
			res.Err = "headers: " + err.Error()
			return res
		}
		if strings.TrimSpace(h) == "" {
			break
		}
	}
	want := int64(96 * 1024)
	var got int64
	buf := make([]byte, 32*1024)
	for {
		n, err := rdr.Read(buf)
		got += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			res.Err = "body: " + err.Error()
			return res
		}
	}
	if got < want {
		res.Err = "short body: " + strconv.FormatInt(got, 10) + "/" + strconv.FormatInt(want, 10)
		return res
	}
	res.OK = true
	return res
}

// freeLocalPort finds a free TCP port inside [lo, hi].
func freeLocalPort(lo, hi int) (int, error) {
	for p := lo; p < hi; p += 7 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p, nil
		}
	}
	return 0, fmt.Errorf("no free port")
}

// doctorRun tests every enabled transport through one address (best edge when
// available) and stores the verdicts. Runs after each auto-scan + on demand.
func doctorRun() bool {
	doctorMu.Lock()
	if doctorRunning {
		doctorMu.Unlock()
		return false
	}
	doctorRunning = true
	doctorMu.Unlock()
	defer func() { doctorMu.Lock(); doctorRunning = false; doctorMu.Unlock() }()

	domain := autoScanDomain()
	if domain == "" {
		return false
	}
	stateMu.RLock()
	addr := ""
	if len(state.TopEdges) > 0 {
		addr = state.TopEdges[0].IP
	} else if isIPLiteral(strings.TrimSpace(state.Address)) {
		addr = strings.TrimSpace(state.Address)
	}
	clients := append([]*Client(nil), activeClientsLocked()...)
	stateMu.RUnlock()
	if addr == "" || len(clients) == 0 {
		return false
	}
	results := map[string]DocRes{}
	for _, key := range doctorKeys {
		if !protoEnabled(key) {
			continue
		}
		// pick the first user that actually has this transport enabled —
		// probing with a UUID the server doesn't know would false-alarm.
		var client *Client
		for _, c := range clients {
			if userProtocols(c)[key] {
				client = c
				break
			}
		}
		if client == nil {
			results[key] = DocRes{OK: false, Edge: addr, Err: "no user with this transport enabled"}
			continue
		}
		results[key] = doctorOne(client, key, addr, domain)
	}
	stateMu.Lock()
	state.Doctor = results
	state.DoctorAt = time.Now().Unix()
	stateMu.Unlock()
	saveState()
	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
		}
	}
	logf("doctor: %d/%d transports healthy through %s", okCount, len(results), addr)
	return true
}

// doctorRunningNow / doctorPayload are small locked readers for the API.
func doctorRunningNow() bool {
	doctorMu.Lock()
	defer doctorMu.Unlock()
	return doctorRunning
}

func doctorPayload() (map[string]DocRes, int64, bool) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	m := map[string]DocRes{}
	for k, v := range state.Doctor {
		m[k] = v
	}
	return m, state.DoctorAt, doctorRunningNow()
}
