package main

import (
	"os"
	"strings"
	"sync"
)

// ─────────── kernel speed tuning: BBR + fq + big buffers ───────────
// Applied by the installer AND self-healed on every panel boot (root only).
// These are the levers that actually move throughput on long-fat Iranian
// routes (Tehran→EU ≈ 90-160ms RTT): BBR keeps single-flow speed high under
// loss, fq paces it, and 32MB socket buffers let the window open fully.

var speedSysctls = map[string]string{
	"net.core.default_qdisc":            "fq",
	"net.ipv4.tcp_congestion_control":   "bbr",
	"net.core.rmem_max":                 "33554432",
	"net.core.wmem_max":                 "33554432",
	"net.ipv4.tcp_rmem":                 "4096 87380 33554432",
	"net.ipv4.tcp_wmem":                 "4096 65536 33554432",
	"net.ipv4.tcp_mtu_probing":          "1",
	"net.ipv4.tcp_fastopen":             "3",
	"net.core.somaxconn":                "4096",
	"net.ipv4.tcp_notsent_lowat":        "16384",
	"net.ipv4.ip_local_port_range":      "1024 65535",
	"net.ipv4.tcp_slow_start_after_idle": "0",
	"net.ipv4.tcp_window_scaling":       "1",
	"net.ipv4.tcp_sack":                 "1",
	"net.ipv4.tcp_timestamps":           "1",
}

var (
	sysctlMu   sync.Mutex
	sysctlDone bool
)

// applySysctls writes every knob when possible; silent no-op without root.
func applySysctls() {
	sysctlMu.Lock()
	defer sysctlMu.Unlock()
	if sysctlDone {
		return
	}
	sysctlDone = true
	applied := true
	for key, val := range speedSysctls {
		p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		if b, err := os.ReadFile(p); err == nil {
			cur := strings.TrimSpace(string(b))
			if cur == val {
				continue
			}
			if err := os.WriteFile(p, []byte(val), 0o644); err != nil {
				applied = false
			}
		} else {
			applied = false
		}
	}
	stateMu.Lock()
	state.SysctlOK = applied
	saveStateLocked()
	stateMu.Unlock()
	if applied {
		logf("speed: BBR + fq + 32MB buffers applied (kernel tuning active)")
	} else {
		logf("speed: kernel tuning partially unavailable (need root; installer applies it via sysctl.conf)")
	}
}

// sysctlStatus reports whether the tuning is active right now.
func sysctlStatus() (map[string]string, bool) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return nil, false
	}
	if strings.TrimSpace(string(b)) != "bbr" {
		return nil, false
	}
	return map[string]string{"cc": "bbr"}, true
}
