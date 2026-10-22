package main

// ─────────── install-bot E2E tests against a fake Telegram + fake Lucity ───────────

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────── fakes ───────────

type tgRecorder struct {
	mu      sync.Mutex
	sent    map[int64][]string
	edits   map[int64][]string
	deleted map[int64][]int64
	counter int64
}

func newRecorder() *tgRecorder {
	return &tgRecorder{
		sent:    map[int64][]string{},
		edits:   map[int64][]string{},
		deleted: map[int64][]int64{},
	}
}

func (r *tgRecorder) addSent(chat int64, text string) {
	r.mu.Lock()
	r.sent[chat] = append(r.sent[chat], text)
	r.mu.Unlock()
}

func (r *tgRecorder) addEdit(chat int64, text string) {
	r.mu.Lock()
	r.edits[chat] = append(r.edits[chat], text)
	r.mu.Unlock()
}

func (r *tgRecorder) addDeleted(chat int64, id int64) {
	r.mu.Lock()
	r.deleted[chat] = append(r.deleted[chat], id)
	r.mu.Unlock()
}

// waitSent polls until a sendMessage to chat contains substr; returns it.
func (r *tgRecorder) waitSent(chat int64, substr string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, t := range r.sent[chat] {
			if strings.Contains(t, substr) {
				r.mu.Unlock()
				return t
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

func (r *tgRecorder) waitEdit(chat int64, substr string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, t := range r.edits[chat] {
			if strings.Contains(t, substr) {
				r.mu.Unlock()
				return t
			}
		}
		r.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

type fakeLucity struct {
	mu               sync.Mutex
	projectCreated   bool
	volumeID         string
	serviceID        string
	healthy          bool
	healthyAfterPoll int // >0: become HEALTHY only after N status polls
	statusPolls      int
	addServiceImage  string
	addServiceVars   map[string]string
	varCalls         []map[string]string
	portCalls        []int
	healthCheckSet   bool
	loginHits        int
	ghcrPublic       bool
	host             string // mock host:port
}

func mockWriteJSON(w http.ResponseWriter, obj any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(obj)
}

// newFake wires one httptest server that plays BOTH the Telegram Bot API
// (under /tg/) and Lucity (/auth/config, /logto/token, /graphql, /panel/api/login).
func newFake(t *testing.T) (*fakeLucity, *httptest.Server, *tgRecorder) {
	t.Helper()
	rec := newRecorder()
	f := &fakeLucity{addServiceVars: map[string]string{}}

	mux := http.NewServeMux()

	// —— Telegram mock ——
	mux.HandleFunc("/tg/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/tg/bot")
		if !strings.HasPrefix(rest, "6:test-token-abcdefghijklmnop/") {
			mockWriteJSON(w, map[string]any{"ok": false, "description": "unauthorized"})
			return
		}
		method := strings.TrimPrefix(rest, "6:test-token-abcdefghijklmnop/")
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		switch method {
		case "sendMessage":
			chat, _ := payload["chat_id"].(float64)
			rec.addSent(int64(chat), payload["text"].(string))
			rec.mu.Lock()
			rec.counter++
			id := rec.counter
			rec.mu.Unlock()
			mockWriteJSON(w, map[string]any{"ok": true, "result": map[string]any{"message_id": id}})
		case "editMessageText":
			chat, _ := payload["chat_id"].(float64)
			rec.addEdit(int64(chat), payload["text"].(string))
			mockWriteJSON(w, map[string]any{"ok": true, "result": map[string]any{"message_id": payload["message_id"]}})
		case "deleteMessage":
			chat, _ := payload["chat_id"].(float64)
			mid, _ := payload["message_id"].(float64)
			rec.addDeleted(int64(chat), int64(mid))
			mockWriteJSON(w, map[string]any{"ok": true, "result": true})
		case "getMe":
			mockWriteJSON(w, map[string]any{"ok": true, "result": map[string]any{"id": 42, "username": "deepnetwork_install_bot"}})
		case "getUpdates", "setMyCommands", "deleteWebhook":
			mockWriteJSON(w, map[string]any{"ok": true, "result": []any{}})
		default:
			mockWriteJSON(w, map[string]any{"ok": false, "description": "unknown method " + method})
		}
	})

	// —— Lucity auth ——
	mux.HandleFunc("/auth/config", func(w http.ResponseWriter, r *http.Request) {
		mockWriteJSON(w, map[string]any{"issuer": "http://" + f.host + "/logto", "audience": "aud"})
	})
	mux.HandleFunc("/logto/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("cid:secret")) {
			mockWriteJSON(w, map[string]any{"error": "bad credentials"})
			return
		}
		mockWriteJSON(w, map[string]any{"access_token": "acc-1"})
	})

	// —— Lucity GraphQL ——
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer acc-1" {
			mockWriteJSON(w, map[string]any{"errors": []any{map[string]any{"message": "unauthenticated"}}})
			return
		}
		var body struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		q := body.Query
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.Contains(q, "createProject"):
			f.projectCreated = true
			mockWriteJSON(w, map[string]any{"data": map[string]any{"createProject": map[string]any{"id": "test-ws/deep-network"}}})
		case strings.Contains(q, "createVolume"):
			f.volumeID = "vol-1"
			mockWriteJSON(w, map[string]any{"data": map[string]any{"createVolume": map[string]any{"id": "vol-1"}}})
		case strings.Contains(q, "addService"):
			input, _ := body.Variables["input"].(map[string]any)
			f.addServiceImage, _ = input["image"].(string)
			if vars, ok := input["variables"].([]any); ok {
				for _, v0 := range vars {
					v, _ := v0.(map[string]any)
					k, _ := v["key"].(string)
					val, _ := v["value"].(string)
					f.addServiceVars[k] = val
				}
			}
			f.serviceID = "svc-1"
			mockWriteJSON(w, map[string]any{"data": map[string]any{"addService": map[string]any{"id": "svc-1", "name": "deep-network"}}})
		case strings.Contains(q, "setServiceVariables"):
			vars := map[string]string{}
			if vs, ok := body.Variables["variables"].([]any); ok {
				for _, v0 := range vs {
					v, _ := v0.(map[string]any)
					k, _ := v["key"].(string)
					val, _ := v["value"].(string)
					vars[k] = val
				}
			}
			f.varCalls = append(f.varCalls, vars)
			mockWriteJSON(w, map[string]any{"data": map[string]any{"setServiceVariables": true}})
		case strings.Contains(q, "setServicePort"):
			port, _ := body.Variables["port"].(float64)
			f.portCalls = append(f.portCalls, int(port))
			mockWriteJSON(w, map[string]any{"data": map[string]any{"setServicePort": map[string]any{"id": "svc-1"}}})
		case strings.Contains(q, "mountVolume"):
			mockWriteJSON(w, map[string]any{"data": map[string]any{"mountVolume": map[string]any{"id": "vol-1"}}})
		case strings.Contains(q, "generateDomain"):
			mockWriteJSON(w, map[string]any{"data": map[string]any{"generateDomain": map[string]any{
				"endpoints": []any{map[string]any{"host": f.host, "protocol": "https", "tls": "TRUE"}},
			}}})
		case strings.Contains(q, "setServiceHealthCheck"):
			f.healthCheckSet = true
			if f.healthyAfterPoll <= 0 {
				f.healthy = true
			}
			mockWriteJSON(w, map[string]any{"data": map[string]any{"setServiceHealthCheck": map[string]any{"id": "svc-1"}}})
		case strings.Contains(q, "service(id: $id)"):
			f.statusPolls++
			if f.healthyAfterPoll > 0 && f.statusPolls >= f.healthyAfterPoll {
				f.healthy = true
			}
			status := "BUILDING"
			if f.healthy {
				status = "HEALTHY"
			}
			mockWriteJSON(w, map[string]any{"data": map[string]any{"service": map[string]any{
				"status":    status,
				"endpoints": []any{map[string]any{"host": f.host, "protocol": "https", "tls": "TRUE"}},
			}}})
		default: // snapshot
			projects := []any{}
			if f.projectCreated {
				svcs := []any{}
				if f.serviceID != "" {
					svcs = append(svcs, map[string]any{"id": f.serviceID, "name": "deep-network"})
				}
				vols := []any{}
				if f.volumeID != "" {
					vols = append(vols, map[string]any{"id": f.volumeID, "name": "deep-data", "size": "10Gi"})
				}
				projects = append(projects, map[string]any{
					"id": "test-ws/deep-network", "name": "DEEP NETWORK",
					"environments": []any{map[string]any{
						"id": "test-ws/deep-network/development", "name": "development",
						"services": svcs, "volumes": vols,
					}},
				})
			}
			mockWriteJSON(w, map[string]any{"data": map[string]any{
				"workspace": map[string]any{"id": "w1", "name": "test-ws", "suspended": false},
				"projects":  projects,
			}})
		}
	})

	// —— ghcr mock (public image pre-check) ——
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mockWriteJSON(w, map[string]any{"token": "ghcr-anon-token"})
	})
	mux.HandleFunc("/v2/0xakiravx/deep-network/manifests/latest", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		pub := f.ghcrPublic
		f.mu.Unlock()
		if !pub {
			w.WriteHeader(404)
			return
		}
		mockWriteJSON(w, map[string]any{"schemaVersion": 2})
	})

	// —— panel login verification target ——
	mux.HandleFunc("/panel/api/login", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.loginHits++
		f.mu.Unlock()
		mockWriteJSON(w, map[string]any{"ok": true})
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: mux}}
	srv.Start()
	t.Cleanup(srv.Close)

	f.host = strings.TrimPrefix(srv.URL, "http://")

	// point the package at the fakes
	lucityBase = srv.URL
	tgAPIBase = srv.URL + "/tg"
	panelURLScheme = "http"
	installBotToken = "6:test-token-abcdefghijklmnop"
	installPollDelay = 20 * time.Millisecond
	ghcrBase = srv.URL
	atomic.StoreInt64(&ghcrImageOKUnix, 0)
	f.ghcrPublic = true
	return f, srv, rec
}

func mkToken(clientID, secret, org, ws string) string {
	return "lucity_" + base64.RawURLEncoding.EncodeToString([]byte(clientID+":"+secret+":"+org+":"+ws))
}

func feed(chat, msgID int64, text, chatType string) {
	ibotProcess(tgUpdateT{
		UpdateID: msgID,
		Message: &tgMessageT{
			MessageID: msgID,
			Chat:      &tgChatT{ID: chat, Type: chatType},
			Text:      text,
		},
	})
}

// ─────────── tests ───────────

func TestInstallBotFullFlow(t *testing.T) {
	f, _, rec := newFake(t)

	// /start → welcome
	feed(101, 1, "/start", "private")
	if m := rec.waitSent(101, "lucity.cloud", 3*time.Second); m == "" {
		t.Fatal("welcome message not sent")
	}

	// token → full install → credentials
	feed(101, 2, mkToken("cid", "secret", "org1", "test-ws"), "private")

	final := rec.waitSent(101, "آماده شد", 30*time.Second)
	if final == "" {
		t.Fatal("final credentials message not sent")
	}
	if !strings.Contains(final, "http://"+f.host+"/panel") {
		t.Fatalf("final message missing panel URL:\n%s", final)
	}
	if !strings.Contains(final, "admin") || !strings.Contains(final, "پسورد") {
		t.Fatalf("final message missing credentials:\n%s", final)
	}
	f.mu.Lock()
	pass := f.addServiceVars["ADMIN_PASSWORD"]
	img := f.addServiceImage
	varCalls := append([]map[string]string(nil), f.varCalls...)
	portCalls := append([]int(nil), f.portCalls...)
	hc := f.healthCheckSet
	loginHits := f.loginHits
	f.mu.Unlock()

	if pass == "" || !strings.Contains(final, pass) {
		t.Fatalf("ADMIN_PASSWORD not pinned or not delivered (pass=%q)", pass)
	}
	if img != "ghcr.io/0xakiravx/deep-network:latest" {
		t.Fatalf("service created from wrong image: %q", img)
	}
	if !hc {
		t.Fatal("health check never set")
	}
	if loginHits < 1 {
		t.Fatal("panel login never verified")
	}
	if len(portCalls) != 1 || portCalls[0] != 8080 {
		t.Fatalf("port calls wrong: %v", portCalls)
	}
	var domainSet bool
	for _, vc := range varCalls {
		if vc["DOMAIN"] == f.host {
			domainSet = true
		}
	}
	if !domainSet {
		t.Fatalf("DOMAIN variable never set to %s: %+v", f.host, varCalls)
	}
	if strings.Contains(final, "⚠️") {
		t.Fatalf("login verification failed in final message:\n%s", final)
	}

	// the user's token message must have been deleted
	rec.mu.Lock()
	deleted := append([]int64(nil), rec.deleted[101]...)
	rec.mu.Unlock()
	found := false
	for _, d := range deleted {
		if d == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("token message not deleted")
	}
}

func TestInstallBotAlreadyInstalled(t *testing.T) {
	f, _, rec := newFake(t)
	f.mu.Lock()
	f.projectCreated = true
	f.serviceID = "svc-existing" // an existing deep-network service
	f.mu.Unlock()

	feed(202, 5, mkToken("cid", "secret", "org1", "test-ws"), "private")
	m := rec.waitEdit(202, "از قبل", 30*time.Second)
	if m == "" {
		t.Fatal("already-installed message not sent")
	}
}

func TestInstallBotBadTokensAndCooldown(t *testing.T) {
	_, _, rec := newFake(t)

	for i := 0; i < 3; i++ {
		feed(303, int64(10+i), "lucity_zzz", "private")
	}
	if m := rec.waitEdit(303, "قالب توکن معتبر نیست", 5*time.Second); m == "" {
		t.Fatal("format error not reported")
	}

	// a now-valid token must be rejected by the cooldown
	feed(303, 99, mkToken("cid", "secret", "org1", "test-ws"), "private")
	if m := rec.waitSent(303, "۱۰ دقیقه", 5*time.Second); m == "" {
		t.Fatal("cooldown message not sent after repeated failures")
	}
}

func TestInstallBotUnknownTextCancelAndGroups(t *testing.T) {
	_, _, rec := newFake(t)

	feed(404, 20, "سلام چطوری", "private")
	if m := rec.waitSent(404, "/start", 3*time.Second); m == "" {
		t.Fatal("unknown text did not get the /start hint")
	}

	feed(404, 21, "/cancel", "private")
	if m := rec.waitSent(404, "نصبی در جریان نیست", 3*time.Second); m == "" {
		t.Fatal("idle /cancel did not answer")
	}

	// /start@botname must work like /start
	feed(404, 22, "/start@deepnetwork_install_bot", "private")
	if m := rec.waitSent(404, "lucity.cloud", 3*time.Second); m == "" {
		t.Fatal("/start@botname ignored")
	}

	// group chats must stay silent
	feed(555, 30, "/start", "group")
	time.Sleep(150 * time.Millisecond)
	rec.mu.Lock()
	n := len(rec.sent[555])
	rec.mu.Unlock()
	if n != 0 {
		t.Fatalf("group chat got %d replies, want 0", n)
	}
}

func TestInstallBotImageNotPublic(t *testing.T) {
	f, _, rec := newFake(t)
	f.mu.Lock()
	f.ghcrPublic = false // image not published yet
	f.mu.Unlock()

	feed(606, 70, mkToken("cid", "secret", "org1", "test-ws"), "private")
	if m := rec.waitEdit(606, "ایمیج عمومی پنل", 10*time.Second); m == "" {
		t.Fatal("missing clear not-published error")
	}
	// nothing should have been created on Lucity
	f.mu.Lock()
	created := f.serviceID != "" || f.volumeID != ""
	f.mu.Unlock()
	if created {
		t.Fatal("service was created although the image was not public")
	}
}

func TestInstallBotBusyWhileInstalling(t *testing.T) {
	f, _, rec := newFake(t)
	f.mu.Lock()
	f.healthyAfterPoll = 6 // keep the install busy for a while
	f.mu.Unlock()

	feed(505, 60, mkToken("cid", "secret", "org1", "test-ws"), "private")

	// a second token while the first install is running
	ok := make(chan string, 1)
	go func() {
		feed(505, 61, mkToken("cid", "secret", "org1", "test-ws"), "private")
		ok <- rec.waitSent(505, "در جریان است", 10*time.Second)
	}()
	if m := <-ok; m == "" {
		t.Fatal("second token during install did not get the busy message")
	}

	// and the original install must still finish
	if m := rec.waitSent(505, "آماده شد", 30*time.Second); m == "" {
		t.Fatal("original install did not finish")
	}
}
