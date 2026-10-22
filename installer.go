package main

// ─────────── Telegram installer bot — Lucity client + install pipeline ───────────
// (v3.5) A user sends their Lucity API token to the bot; the bot then
// deploys a complete DEEP NETWORK panel on the user's OWN Lucity
// workspace from the public ghcr.io image — project, 10Gi volume at
// /data, service with a pinned admin password, platform domain and an
// HTTP health check — and finally hands back the panel link with the
// admin credentials. No GitHub, no dashboard, no terminal needed.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────── Lucity GraphQL client ───────────

var (
	lucityBase         = "https://lucity.cloud" // var (not const) so tests can point it at a mock
	installImage       = "ghcr.io/0xakiravx/deep-network:latest"
	installProjectID   = "deep-network"
	installVolumeName  = "deep-data"
	installVolumeSize  = "10Gi"
	installServiceName = "deep-network"

	ghcrBase        = "https://ghcr.io" // var so tests can point it at a mock
	ghcrImageOKUnix int64               // unix time of last confirmed public manifest (atomic)
)

// checkInstallImage verifies the public ghcr manifest is actually
// reachable, so the bot can explain — instead of failing deep inside
// Lucity — when the image is not published / not public yet. Definitive
// 401/403/404 → clear Persian error; network oddities → proceed anyway.
func checkInstallImage() error {
	if ok := atomic.LoadInt64(&ghcrImageOKUnix); ok != 0 && time.Since(time.Unix(ok, 0)) < 5*time.Minute {
		return nil
	}
	repo := strings.TrimPrefix(strings.TrimSuffix(installImage, ":latest"), "ghcr.io/")
	tokURL := ghcrBase + "/token?service=ghcr.io&scope=repository:" + repo + ":pull"
	resp, err := lucityHTTP.Get(tokURL)
	if err != nil {
		return nil
	}
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
	resp.Body.Close()
	if out.Token == "" {
		return nil
	}
	req, _ := http.NewRequest("GET", ghcrBase+"/v2/"+repo+"/manifests/latest", nil)
	req.Header.Set("Authorization", "Bearer "+out.Token)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json")
	resp2, err := lucityHTTP.Do(req)
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp2.Body, 4096))
	resp2.Body.Close()
	switch resp2.StatusCode {
	case 200:
		atomic.StoreInt64(&ghcrImageOKUnix, time.Now().Unix())
		return nil
	case 401, 403, 404:
		return fmt.Errorf("ایمیج عمومی پنل هنوز در دسترس نیست (ghcr.io/%s) — مدتی بعد دوباره تلاش کن", repo)
	}
	return nil
}

var lucityHTTP = &http.Client{Timeout: 45 * time.Second}

type lucityClient struct {
	access    string
	workspace string
}

// lucityExchange validates a raw lucity_… API token and swaps it for a
// short-lived access token (client-credentials flow against Logto).
func lucityExchange(raw string) (*lucityClient, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "lucity_") {
		return nil, fmt.Errorf("توکن باید با lucity_ شروع شود")
	}
	// Lucity tokens are unpadded url-safe base64; tolerate padded input too
	enc := strings.TrimRight(strings.TrimPrefix(raw, "lucity_"), "=")
	dec, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("قالب توکن معتبر نیست")
	}
	parts := strings.SplitN(string(dec), ":", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("قالب توکن معتبر نیست")
	}
	clientID, secret, orgID, workspace := parts[0], parts[1], parts[2], parts[3]

	// 1) discovery
	cfgReq, _ := http.NewRequest("GET", lucityBase+"/auth/config", nil)
	cfgReq.Header.Set("User-Agent", "DeepNetwork/"+Version)
	resp, err := lucityHTTP.Do(cfgReq)
	if err != nil {
		return nil, fmt.Errorf("اتصال به Lucity برقرار نشد")
	}
	var cfg struct {
		Issuer   string `json:"issuer"`
		Audience string `json:"audience"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&cfg)
	resp.Body.Close()
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("پاسخ نامعتبر از Lucity")
	}

	// 2) client-credentials token exchange
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("resource", cfg.Audience)
	form.Set("organization_id", orgID)
	form.Set("scope", "admin member deployer")
	tokReq, _ := http.NewRequest("POST", strings.TrimRight(cfg.Issuer, "/")+"/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(clientID, secret)
	resp, err = lucityHTTP.Do(tokReq)
	if err != nil {
		return nil, fmt.Errorf("اتصال به سرور ورود Lucity برقرار نشد")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("توکن پذیرفته نشد (کد %d)", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		return nil, fmt.Errorf("پاسخ نامعتبر از سرور ورود")
	}
	return &lucityClient{access: out.AccessToken, workspace: workspace}, nil
}

// gql runs one GraphQL request; returns data + first error message.
func (l *lucityClient) gql(query string, variables map[string]any) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	req, err := http.NewRequest("POST", lucityBase+"/graphql", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.access)
	req.Header.Set("X-Lucity-Workspace", l.workspace)
	req.Header.Set("User-Agent", "DeepNetwork/"+Version)
	resp, err := lucityHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ارتباط با Lucity قطع شد")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Data   map[string]any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(b, &out) != nil {
		return nil, fmt.Errorf("پاسخ نامعتبر از Lucity")
	}
	if len(out.Errors) > 0 {
		return out.Data, fmt.Errorf("%s", out.Errors[0].Message)
	}
	return out.Data, nil
}

// ─────────── workspace snapshot ───────────

type lucityEnv struct {
	EnvID    string
	Services []string // service names
	Volumes  []lucityVol
}

type lucityVol struct {
	ID        string
	Name      string
	MountedTo string // service id or ""
}

type lucitySnapshot struct {
	WorkspaceID string
	Workspace   string
	Suspended   bool
	Env         *lucityEnv // development environment of the deep-network project
}

const gqlSnapshot = `query {
  workspace { id name suspended }
  projects { id name environments { id name services { id name } volumes { id name size mount { service path } } } }
}`

func lucityEnvID(ws, project string) string { return ws + "/" + project + "/development" }

func (l *lucityClient) snapshot() (*lucitySnapshot, error) {
	data, err := l.gql(gqlSnapshot, nil)
	if err != nil {
		return nil, err
	}
	snap := &lucitySnapshot{}
	if w, ok := data["workspace"].(map[string]any); ok {
		snap.WorkspaceID, _ = w["id"].(string)
		snap.Workspace, _ = w["name"].(string)
		snap.Suspended, _ = w["suspended"].(bool)
	}
	if projects, ok := data["projects"].([]any); ok {
		for _, p0 := range projects {
			p, _ := p0.(map[string]any)
			if p == nil || p["id"] != wsProjectPath(l.workspace) {
				continue
			}
			if envs, ok := p["environments"].([]any); ok {
				for _, e0 := range envs {
					e, _ := e0.(map[string]any)
					if e == nil || e["name"] != "development" {
						continue
					}
					env := &lucityEnv{EnvID: lucityEnvID(l.workspace, installProjectID)}
					if svcs, ok := e["services"].([]any); ok {
						for _, s0 := range svcs {
							if s, _ := s0.(map[string]any); s != nil {
								if n, _ := s["name"].(string); n != "" {
									env.Services = append(env.Services, n)
								}
							}
						}
					}
					if vols, ok := e["volumes"].([]any); ok {
						for _, v0 := range vols {
							v, _ := v0.(map[string]any)
							if v == nil {
								continue
							}
							lv := lucityVol{ID: str(v, "id"), Name: str(v, "name")}
							if m, _ := v["mount"].(map[string]any); m != nil {
								lv.MountedTo, _ = m["service"].(string)
							}
							env.Volumes = append(env.Volumes, lv)
						}
					}
					snap.Env = env
					return snap, nil
				}
			}
		}
	}
	return snap, nil
}

func wsProjectPath(ws string) string { return ws + "/" + installProjectID }

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// ─────────── install mutations ───────────

func (l *lucityClient) createProject() error {
	_, err := l.gql(`mutation($input: CreateProjectInput!) {
          createProject(input: $input) { id }
        }`, map[string]any{"input": map[string]any{"name": "DEEP NETWORK", "id": installProjectID}})
	return err
}

func (l *lucityClient) createVolume() error {
	_, err := l.gql(`mutation($env: EnvironmentID!, $name: String!, $size: String!) {
          createVolume(environment: $env, name: $name, size: $size) { id }
        }`, map[string]any{"env": lucityEnvID(l.workspace, installProjectID), "name": installVolumeName, "size": installVolumeSize})
	return err
}

func (l *lucityClient) addService(image string, variables map[string]string) (string, error) {
	vars := make([]map[string]string, 0, len(variables))
	for k, v := range variables {
		vars = append(vars, map[string]string{"key": k, "value": v})
	}
	data, err := l.gql(`mutation($env: EnvironmentID!, $input: AddServiceInput!) {
          addService(environment: $env, input: $input) { id name }
        }`, map[string]any{
		"env": lucityEnvID(l.workspace, installProjectID),
		"input": map[string]any{
			"name":      installServiceName,
			"image":     image,
			"variables": vars,
		},
	})
	if err != nil {
		return "", err
	}
	if svc, ok := data["addService"].(map[string]any); ok {
		return str(svc, "id"), nil
	}
	return "", fmt.Errorf("پاسخ سرویس از Lucity نامعتبر بود")
}

func (l *lucityClient) setVariables(service string, variables map[string]string) error {
	vars := make([]map[string]string, 0, len(variables))
	for k, v := range variables {
		vars = append(vars, map[string]string{"key": k, "value": v})
	}
	_, err := l.gql(`mutation($service: ServiceID!, $variables: [ServiceVariableInput!]!) {
          setServiceVariables(service: $service, variables: $variables)
        }`, map[string]any{"service": service, "variables": vars})
	return err
}

func (l *lucityClient) mountVolume(volume, service, path string) error {
	_, err := l.gql(`mutation($volume: VolumeID!, $service: ServiceID!, $path: String!) {
          mountVolume(volume: $volume, service: $service, path: $path) { id }
        }`, map[string]any{"volume": volume, "service": service, "path": path})
	return err
}

func (l *lucityClient) generateDomain(service string) (string, error) {
	data, err := l.gql(`mutation($service: ServiceID!) {
          generateDomain(service: $service) { endpoints { host protocol tls } }
        }`, map[string]any{"service": service})
	if err != nil {
		return "", err
	}
	if svc, ok := data["generateDomain"].(map[string]any); ok {
		if eps, ok := svc["endpoints"].([]any); ok {
			for _, e0 := range eps {
				if e, _ := e0.(map[string]any); e != nil {
					if h := str(e, "host"); h != "" {
						return h, nil
					}
				}
			}
		}
	}
	return "", fmt.Errorf("آدرس پنل ساخته نشد")
}

func (l *lucityClient) setPort(service string, port int) error {
	_, err := l.gql(`mutation($service: ServiceID!, $port: Int) {
          setServicePort(service: $service, port: $port) { id }
        }`, map[string]any{"service": service, "port": port})
	return err
}

func (l *lucityClient) setHealthCheck(service string) error {
	_, err := l.gql(`mutation($service: ServiceID!) {
          setServiceHealthCheck(service: $service, healthCheck: {
            path: "/panel"
            initialDelaySeconds: 10
            periodSeconds: 15
            timeoutSeconds: 5
            failureThreshold: 3
            startupFailureThreshold: 30
          }) { id }
        }`, map[string]any{"service": service})
	return err
}

// serviceStatus returns (status, firstHost).
func (l *lucityClient) serviceStatus(service string) (string, string) {
	data, err := l.gql(`query($id: ServiceID!) {
          service(id: $id) { status endpoints { host protocol tls } }
        }`, map[string]any{"id": service})
	if err != nil {
		return "", ""
	}
	svc, _ := data["service"].(map[string]any)
	if svc == nil {
		return "", ""
	}
	host := ""
	if eps, ok := svc["endpoints"].([]any); ok {
		for _, e0 := range eps {
			if e, _ := e0.(map[string]any); e != nil {
				if h := str(e, "host"); h != "" && (host == "" || str(e, "tls") != "NONE") {
					host = h
				}
			}
		}
	}
	return str(svc, "status"), host
}

// ─────────── install pipeline ───────────

type installResult struct {
	PanelURL  string
	AdminUser string
	AdminPass string
}

// installPanel runs the full deployment on the user's workspace.
// progress(step int, note string) is called as milestones complete.
func installPanel(lc *lucityClient, pass string, progress func(int, string)) (*installResult, error) {
	// 1) workspace + reuse detection
	snap, err := lc.snapshot()
	if err != nil {
		return nil, fmt.Errorf("خواندن اطلاعات اکانت ناموفق بود: %v", err)
	}
	if snap.Suspended {
		return nil, fmt.Errorf("اکانت Lucity شما غیرفعال (suspended) است")
	}
	if snap.Env != nil {
		for _, s := range snap.Env.Services {
			if s == installServiceName {
				return nil, errAlreadyInstalled
			}
		}
	}
	progress(1, wsNote(snap.Workspace))

	// the public panel image must exist before anything is created on
	// the requester's workspace — fail fast with a clear message.
	if err := checkInstallImage(); err != nil {
		return nil, err
	}

	// 2) project + volume
	if snap.Env == nil {
		if err := lc.createProject(); err != nil {
			return nil, classifyInstallErr(err, "ساخت پروژه")
		}
	}
	snap, _ = lc.snapshot()
	var volumeID string
	if snap.Env != nil {
		for _, v := range snap.Env.Volumes {
			if v.Name == installVolumeName {
				volumeID = v.ID
			}
		}
	}
	if volumeID == "" {
		if err := lc.createVolume(); err != nil {
			return nil, classifyInstallErr(err, "ساخت دیسک")
		}
		if snap2, _ := lc.snapshot(); snap2.Env != nil {
			for _, v := range snap2.Env.Volumes {
				if v.Name == installVolumeName {
					volumeID = v.ID
				}
			}
		}
		if volumeID == "" {
			return nil, fmt.Errorf("دیسک ساخته شد اما پیدا نشد")
		}
	}
	progress(2, "")

	// 3) service from the public image, with a pinned admin password
	svcID, err := lc.addService(installImage, map[string]string{
		"ADMIN_PASSWORD": pass,
		"TZ":             "UTC",
	})
	if err != nil {
		return nil, classifyInstallErr(err, "ساخت سرویس")
	}
	_ = lc.setPort(svcID, 8080)
	if volumeID != "" {
		if err := lc.mountVolume(volumeID, svcID, "/data"); err != nil {
			return nil, classifyInstallErr(err, "متصل‌کردن دیسک")
		}
	}
	progress(3, "")

	// 4) domain
	host, err := lc.generateDomain(svcID)
	if err != nil {
		return nil, classifyInstallErr(err, "ساخت آدرس")
	}
	progress(4, "آدرس: "+panelURLScheme+"://"+host)

	// 5) finalize config (DOMAIN must know the real host) + health check
	if err := lc.setVariables(svcID, map[string]string{
		"ADMIN_PASSWORD": pass,
		"DOMAIN":         host,
		"TZ":             "UTC",
	}); err != nil {
		return nil, classifyInstallErr(err, "تنظیم متغیرها")
	}
	if err := lc.setHealthCheck(svcID); err != nil {
		return nil, classifyInstallErr(err, "تنظیم بررسی سلامت")
	}
	progress(5, "")

	// 6) wait HEALTHY
	deadline := time.Now().Add(15 * time.Minute)
	status := ""
	for time.Now().Before(deadline) {
		time.Sleep(installPollDelay)
		st, h := lc.serviceStatus(svcID)
		if h != "" {
			host = h
		}
		if st == "HEALTHY" || st == "DEGRADED" {
			status = st
			break
		}
		if st == "FAILED" {
			return nil, fmt.Errorf("سرویس راه‌اندازی نشد (FAILED) — دوباره تلاش کن")
		}
	}
	if status == "" {
		return nil, fmt.Errorf("راه‌اندازی بیش از ۱۵ دقیقه طول کشید")
	}
	progress(6, "نصب کامل شد — در حال بررسی نهایی…")
	return &installResult{PanelURL: panelURLScheme + "://" + host + "/panel", AdminUser: "admin", AdminPass: pass}, nil
}

func wsNote(ws string) string {
	if ws == "" {
		return ""
	}
	return "اکانت: " + ws
}

var errAlreadyInstalled = fmt.Errorf("already installed")

// classifyInstallErr maps Lucity errors to friendly Persian messages.
func classifyInstallErr(err error, where string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "already exists"), strings.Contains(msg, "exists"):
		return fmt.Errorf("روی این اکانت Lucity از قبل سرویس «deep-network» وجود دارد — اگر پنل قبلی را نمی‌خواهی، اول از داشبورد Lucity آن را حذف کن و دوباره نصب را شروع کن")
	case strings.Contains(msg, "role"), strings.Contains(msg, "permission"), strings.Contains(msg, "forbidden"):
		return fmt.Errorf("توکن دسترسی لازم را ندارد — یک API Token جدید با نقش Admin بساز و دوباره بفرست")
	case strings.Contains(msg, "limit"), strings.Contains(msg, "quota"), strings.Contains(msg, "exceed"):
		return fmt.Errorf("سقف منابع اکانت Lucity پر شده است")
	}
	return fmt.Errorf("%s ناموفق بود: %s", where, msg)
}

// verifyPanelLogin double-checks the generated credentials against the
// freshly installed panel before they are sent to the user.
func verifyPanelLogin(panelURL, user, pass string) bool {
	body, _ := json.Marshal(map[string]string{"user": user, "pass": pass})
	for i := 0; i < 6; i++ {
		req, err := http.NewRequest("POST", panelURL+"/api/login", bytes.NewReader(body))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := lucityHTTP.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		time.Sleep(10 * time.Second)
	}
	return false
}

// ─────────── install bookkeeping ───────────

var (
	installMu       sync.Mutex
	installsRunning int
)

func installsInc(delta int) {
	installMu.Lock()
	installsRunning += delta
	installMu.Unlock()
}

func installsBusy() int {
	installMu.Lock()
	defer installMu.Unlock()
	return installsRunning
}

// randomPassword generates a fresh admin password for a new install
// (same shape the panel itself uses on first boot: a UUID).
func randomPassword() string {
	b := make([]byte, 16)
	randRead(b)
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
