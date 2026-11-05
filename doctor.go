package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─────────── doctor: REAL end-to-end self-test through every transport ───────────
// The panel builds a temporary xray CLIENT config (exactly the JSON a user
// gets from /sub/<token>?fmt=xray), runs it, and fetches a real URL through
// each transport's SOCKS port. This is the same chain v2rayNG executes —
// if the doctor is green, the configs work; any remaining failure is on the
// client/ISP side.
//
// Order: loopback first (proves the xray inbound + Reality auth work — fast
// and always reachable), then the public IP as an external signal (cloud NAT
// hairpin may differ). All three transports run in parallel.

const doctorURL = "https://www.gstatic.com/generate_204"

var doctorMu sync.Mutex

func doctorRun() []DocRes {
	doctorMu.Lock()
	defer doctorMu.Unlock()
	bin := ensureXray()
	if bin == "" || realityPub == "" {
		return []DocRes{{Name: "xray", OK: false, Err: "xray/Reality unavailable", At: time.Now().Unix()}}
	}
	stateMu.RLock()
	var main *Client
	for _, c := range state.Clients {
		if c.ID == mainUUID() {
			main = c
		}
	}
	stateMu.RUnlock()
	if main == nil {
		main = &Client{Name: "main", ID: mainUUID()}
	}
	pub := linkAddr(publicHost())
	ports := effectivePorts()
	snis := effectiveSNIs()

	transports := []struct {
		name string
		net  string
		port int
		sni  string
	}{
		{"Vision (TCP)", "tcp", ports.Vision, snis.Vision},
		{"XHTTP", "xhttp", ports.XHTTP, snis.XHTTP},
		{"gRPC", "grpc", ports.GRPC, snis.GRPC},
	}

	out := make([]DocRes, len(transports))
	var wg sync.WaitGroup
	for i, t := range transports {
		wg.Add(1)
		go func(i int, t struct {
			name string
			net  string
			port int
			sni  string
		}) {
			defer wg.Done()
			res := DocRes{Name: t.name, At: time.Now().Unix()}
			// 1) loopback — proves the inbound + Reality auth
			t0 := time.Now()
			if probeTransport(bin, main.ID, "127.0.0.1", t.net, t.port, t.sni, 20800+i) {
				res.OK = true
				res.MS = time.Since(t0).Milliseconds()
			} else if pub != "" && pub != "127.0.0.1" {
				// 2) public IP — the full external path
				t1 := time.Now()
				if probeTransport(bin, main.ID, pub, t.net, t.port, t.sni, 20800+i) {
					res.OK = true
					res.MS = time.Since(t1).Milliseconds()
				} else {
					res.Err = "tunnel test failed via loopback and public IP"
				}
			} else {
				res.Err = "tunnel test failed (see /panel/api/log)"
			}
			out[i] = res
		}(i, t)
	}
	wg.Wait()

	stateMu.Lock()
	state.Doctor = out
	state.DoctorAt = time.Now().Unix()
	saveStateLocked()
	stateMu.Unlock()
	return out
}

// probeTransport spawns one temporary xray client and fetches doctorURL
// through its SOCKS port.
func probeTransport(bin, uuid, host, net string, port int, sni string, socks int) bool {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	cfg := doctorClientConfig(uuid, host, net, port, sni, socks)
	confPath := fmt.Sprintf("/tmp/dn-doctor-%d.json", socks)
	writeJSON(confPath, cfg)
	defer os.Remove(confPath)
	cmd := exec.Command(bin, "run", "-c", confPath)
	if err := cmd.Start(); err != nil {
		return false
	}
	defer killProc(cmd)
	for attempt := 0; attempt < 7; attempt++ {
		time.Sleep(400 * time.Millisecond)
		if fetchThroughSocks(socks, 4*time.Second) {
			return true
		}
	}
	return false
}

// doctorClientConfig: minimal xray client for ONE transport with its own SOCKS port.
func doctorClientConfig(uuid, host, net string, port int, sni string, socks int) map[string]any {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	stream := map[string]any{
		"network": net, "security": "reality",
		"realitySettings": map[string]any{
			"serverName": sni, "fingerprint": "chrome",
			"publicKey": realityPub, "shortId": realitySID, "spiderX": "/"},
	}
	flow := ""
	switch net {
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"path": xhttpPath(), "host": sni, "mode": "auto"}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": grpcService(), "multiMode": false}
	default:
		flow = "xtls-rprx-vision"
	}
	return map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": []map[string]any{{"tag": "socks", "listen": "127.0.0.1", "port": socks,
			"protocol": "socks", "settings": map[string]any{"udp": true, "auth": "noauth"}}},
		"outbounds": []map[string]any{{
			"tag": "probe", "protocol": "vless",
			"settings": map[string]any{"vnext": []map[string]any{{
				"address": host, "port": port,
				"users": []map[string]any{{"id": uuid, "encryption": "none", "flow": flow}}}}},
			"streamSettings": stream,
		}},
	}
}

func fetchThroughSocks(socks int, timeout time.Duration) bool {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: func(r *http.Request) (*url.URL, error) {
				return url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socks))
			},
		},
	}
	req, _ := http.NewRequest("GET", doctorURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return resp.StatusCode == 204 || resp.StatusCode == 200
}

func killProc(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// doctorLoop: re-run the self-test every 30 minutes (results ride /state).
func doctorLoop() {
	time.Sleep(20 * time.Second)
	for {
		_ = doctorRun()
		time.Sleep(30 * time.Minute)
	}
}

// ─────────── RAHNAMA (user guide file, served as a download) ───────────

func rahnamaText() string {
	host := linkAddr(publicHost())
	ports := effectivePorts()
	snis := effectiveSNIs()
	var b strings.Builder
	b.WriteString("DEEP NETWORK — راهنمای سریع (v" + Version + ")\n")
	b.WriteString(strings.Repeat("═", 56) + "\n\n")
	b.WriteString("۱) ورود به پنل:\n")
	b.WriteString("   http://" + host + "/panel\n")
	b.WriteString("   اولین بار: صفحه ثبت نام می‌آید — نام، نام خانوادگی و عکس را وارد کن،\n")
	b.WriteString("   بعد یوزرنیم و رمز بساز. از آن به بعد همان رمز برای ورود کافی است.\n\n")
	b.WriteString("۲) کانفیگ‌ها (۳ ترنسپورت، همه Reality و بدون نیاز به دامنه):\n")
	b.WriteString(fmt.Sprintf("   • Vision (سریع‌ترین)  → %s:%d  (SNI %s)\n", host, ports.Vision, snis.Vision))
	b.WriteString(fmt.Sprintf("   • XHTTP (مقاوم به DPI) → %s:%d  (SNI %s, مسیر %s)\n", host, ports.XHTTP, snis.XHTTP, xhttpPath()))
	b.WriteString(fmt.Sprintf("   • gRPC  (استریم h2)    → %s:%d  (SNI %s, سرویس %s)\n", host, ports.GRPC, snis.GRPC, grpcService()))
	b.WriteString("\n   همه در لینک اشتراک هستند؛ در v2rayNG فقط لینک اشتراک را اضافه کن:\n")
	if subs := subList(); len(subs) > 0 {
		b.WriteString("   http://" + host + "/sub/" + subs[0].token + "\n")
	}
	b.WriteString("\n۳) اگر همه کانفیگ‌ها -۱ شدند:\n")
	b.WriteString("   • در v2rayNG آدرس تست را عوض کن: تنظیمات → آدرس تست اتصال →\n")
	b.WriteString("     http://www.gstatic.com/generate_204  (آدرس پیش‌فرض cp.cloudflare.com\n")
	b.WriteString("     از سرور جواب نمی‌دهد و باعث -۱ کاذب می‌شود)\n")
	b.WriteString("   • ترتیب امتحان: Vision → XHTTP → gRPC\n")
	b.WriteString("   • تست سلامت سرور: ابزارها → تست سلامت (اگر سبز بود، مشکل سمت\n")
	b.WriteString("     اپراتور است — جبهه SNI را در تنظیمات عوض کن)\n\n")
	b.WriteString("۴) سرعت:\n")
	b.WriteString("   • BBR + fq روی سرور فعال است (خودکار).\n")
	b.WriteString("   • در v2rayNG تنظیم Mux را خاموش نگه دار (پیش‌فرض خاموش است).\n")
	b.WriteString("   • برای دانلود سنگین از Vision استفاده کن.\n\n")
	b.WriteString("۵) رمز را فراموش کردی؟ در سرور:\n")
	b.WriteString("   sudo /opt/deep-network/out --reset-pass\n")
	b.WriteString("   (حساب خالی می‌شود و صفحه ثبت نام دوباره می‌آید)\n\n")
	b.WriteString(strings.Repeat("═", 56) + "\n")
	return b.String()
}

func writeRAHNAMA() string {
	p := filepath.Join(dataDir(), "RAHNAMA.txt")
	_ = os.WriteFile(p, []byte(rahnamaText()), 0o644)
	return p
}
