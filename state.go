package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─────────── persistent state (schema-compatible with the Python v2.9 state.json) ───────────

type Client struct {
	Name      string   `json:"name"`
	ID        string   `json:"id"`
	Quota     int64    `json:"quota,omitempty"`
	ExpireAt  int64    `json:"expire_at,omitempty"`
	Up        int64    `json:"up,omitempty"`
	Down      int64    `json:"down,omitempty"`
	Note      string   `json:"note,omitempty"`
	Protocols []string `json:"protocols,omitempty"`
}

type Inbound struct {
	Tag      string `json:"tag"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
	Security string `json:"security"`
	Port     int    `json:"port,omitempty"`
	LPort    int    `json:"lport,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Path     string `json:"path,omitempty"`
}

type TSnap struct {
	D int64 `json:"d"`
	T int64 `json:"t"`
}

type Tuning struct {
	Enabled      bool   `json:"enabled"`
	Profile      string `json:"profile"`
	FP           string `json:"fp"`
	CipherSuites string `json:"cipher_suites"`
	ALPN         string `json:"alpn"`
	FragOn       bool   `json:"frag_on"`
	FragPackets  string `json:"frag_packets"`
	FragLengths  string `json:"frag_lengths"`
	FragDelays   string `json:"frag_delays"`
	FragMaxsplit string `json:"frag_maxsplit"`
	NoiseOn      bool   `json:"noise_on"`
	NoiseRand    string `json:"noise_rand"`
	NoiseDelay   string `json:"noise_delay"`
}

type State struct {
	UUID         string          `json:"uuid"`
	AdminUser    string          `json:"admin_user"`
	AdminPass    string          `json:"admin_pass"`
	Address      string          `json:"address"`
	RealitySNI   string          `json:"reality_sni"`
	CfgFmt       string          `json:"cfg_fmt"`
	Protocols    map[string]bool `json:"protocols"`
	SessionHours int             `json:"session_hours"`
	SNIOverride  string          `json:"sni_override"`
	PassIsAuto   bool            `json:"pass_is_auto"`
	RandomSNI    bool            `json:"random_sni"`
	Tuning       *Tuning         `json:"tuning"`
	TuningV      int             `json:"tuning_v,omitempty"`
	Clients      []*Client       `json:"clients"`
	Inbounds     []*Inbound      `json:"inbounds"`
	TSnaps       []TSnap         `json:"tsnaps,omitempty"`
}

var (
	stateMu sync.RWMutex
	state   *State

	sessionsMu sync.Mutex
	sessions   = map[string]time.Time{}
	loginFails = map[string][]time.Time{}
)

const defaultSessionHours = 12
const loginFailWindow = 10 * time.Minute

var protoKeys = []string{"vless-ws", "vless-xhttp", "vless-hu", "vmess-ws", "trojan-ws", "vless-reality"}

var protoLabels = map[string]string{
	"vless-ws": "VLESS · WebSocket", "vless-xhttp": "VLESS · XHTTP",
	"vless-hu": "VLESS · HTTPUpgrade", "vmess-ws": "VMess · WebSocket",
	"trojan-ws": "Trojan · WebSocket", "vless-reality": "VLESS · Reality (TCP)",
}

func statePath() string {
	d := os.Getenv("DATA_DIR")
	if d == "" {
		d = "/data"
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		d = "/tmp"
	}
	probe := filepath.Join(d, ".t")
	if f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
		d = "/tmp"
	} else {
		f.Close()
		os.Remove(probe)
	}
	return filepath.Join(d, "state.json")
}

func dataDir() string { return filepath.Dir(statePath()) }

func saveStateLocked() {
	b, _ := json.Marshal(state)
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err == nil {
		os.Rename(tmp, statePath())
	}
}

func envStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		var n int
		if _, err := fmtSscan(v, &n); err == nil {
			return n
		}
	}
	return def
}

var pathRe = regexp.MustCompile(`^/[A-Za-z0-9/_\-.]*$`)

func normPath(value, def string) string {
	p := strings.TrimSpace(value)
	if p == "" {
		p = def
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return def
	}
	if !pathRe.MatchString(p) {
		return def
	}
	return p
}

func uuidv4() string {
	b := make([]byte, 16)
	randRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func randHex(n int) string {
	b := make([]byte, n)
	randRead(b)
	return hex.EncodeToString(b)
}

// subToken derives the stable per-user subscription token from SECRET.
func subToken(cid string) string {
	mac := hmac.New(sha256.New, []byte(secret()))
	mac.Write([]byte("sub:" + cid))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func secret() string {
	if s := os.Getenv("SECRET"); s != "" {
		return s
	}
	return mainUUID()
}

func mainUUID() string {
	if s := os.Getenv("UUID"); s != "" {
		return s
	}
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state != nil && state.UUID != "" {
		return state.UUID
	}
	return ""
}

func clientStatus(c *Client, now time.Time) string {
	if c.ExpireAt != 0 && now.Unix() >= c.ExpireAt {
		return "expired"
	}
	if c.Quota != 0 && c.Up+c.Down >= c.Quota {
		return "quota"
	}
	return "active"
}

// userProtocols resolves the effective protocol set (per-user override wins).
func userProtocols(c *Client) map[string]bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return userProtocolsLocked(c)
}

func userProtocolsLocked(c *Client) map[string]bool {
	out := map[string]bool{}
	if len(c.Protocols) > 0 {
		for _, k := range c.Protocols {
			out[k] = true
		}
		return out
	}
	for _, k := range protoKeys {
		if state.Protocols == nil || state.Protocols[k] {
			out[k] = true
		}
	}
	return out
}

func protoEnabled(key string) bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state.Protocols == nil {
		return true
	}
	v, ok := state.Protocols[key]
	return !ok || v
}

func activeClientsLocked() []*Client {
	now := time.Now()
	var out []*Client
	for _, c := range state.Clients {
		if clientStatus(c, now) == "active" {
			out = append(out, c)
		}
	}
	return out
}

func sessionTTL() time.Duration {
	stateMu.RLock()
	h := state.SessionHours
	stateMu.RUnlock()
	if h < 1 {
		h = defaultSessionHours
	}
	if h > 336 {
		h = 336
	}
	return time.Duration(h) * time.Hour
}

func pruneSessions() {
	now := time.Now()
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	for t, exp := range sessions {
		if !exp.After(now) {
			delete(sessions, t)
		}
	}
	for ip, times := range loginFails {
		var recent []time.Time
		for _, x := range times {
			if now.Sub(x) < loginFailWindow {
				recent = append(recent, x)
			}
		}
		if len(recent) > 0 {
			loginFails[ip] = recent
		} else {
			delete(loginFails, ip)
		}
	}
}

func loadState() {
	p := statePath()
	st := &State{}
	rawKeys := map[string]json.RawMessage{}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, st)
		_ = json.Unmarshal(b, &rawKeys)
	}
	if st.UUID == "" {
		st.UUID = envStr("UUID", uuidv4())
	}
	if envStr("UUID", "") != "" {
		st.UUID = envStr("UUID", "")
	}
	if st.AdminUser == "" {
		st.AdminUser = envStr("ADMIN_USER", "admin")
	}
	if st.AdminPass == "" {
		st.AdminPass = envStr("ADMIN_PASSWORD", mainIDFrom(st))
	}
	if st.RealitySNI == "" {
		st.RealitySNI = "www.microsoft.com"
	}
	if st.CfgFmt == "" {
		st.CfgFmt = "{name}-{label}"
	}
	if st.Protocols == nil {
		st.Protocols = map[string]bool{}
		for _, k := range protoKeys {
			st.Protocols[k] = true
		}
	} else {
		for _, k := range protoKeys {
			if _, ok := st.Protocols[k]; !ok {
				st.Protocols[k] = true
			}
		}
	}
	if st.SessionHours < 1 {
		st.SessionHours = defaultSessionHours
	}
	st.PassIsAuto = st.PassIsAuto || os.Getenv("ADMIN_PASSWORD") == ""
	if _, ok := rawKeys["random_sni"]; !ok {
		st.RandomSNI = true
	}
	if _, ok := rawKeys["pass_is_auto"]; !ok {
		st.PassIsAuto = os.Getenv("ADMIN_PASSWORD") == ""
	}
	if st.Tuning == nil {
		st.Tuning = defaultTuning()
	} else {
		st.Tuning = tuningSanitize(st.Tuning)
	}
	if st.TuningV < 2 {
		st.TuningV = 2
		if st.Tuning.Profile == "auto" && st.Tuning.FragLengths == "10-20" && st.Tuning.FragDelays == "10-20" {
			st.Tuning = defaultTuning()
		}
	}
	var clients []*Client
	for _, c := range st.Clients {
		if c.ID != "" && c.Name != "" {
			clients = append(clients, c)
		}
	}
	st.Clients = clients
	main := mainIDFrom(st)
	hasMain := false
	for _, c := range st.Clients {
		if c.ID == main {
			hasMain = true
		}
	}
	if !hasMain {
		st.Clients = append([]*Client{{Name: "main", ID: main}}, st.Clients...)
	}
	state = st
	b, _ := json.Marshal(st)
	_ = os.WriteFile(p, b, 0o644)
}

func mainIDFrom(st *State) string {
	if s := os.Getenv("UUID"); s != "" {
		return s
	}
	return st.UUID
}

// sortedProtoKeys returns the user's protocol keys in canonical order.
func sortedProtoKeys(c *Client) []string {
	m := userProtocols(c)
	var out []string
	for _, k := range protoKeys {
		if m[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
