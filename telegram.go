package main

// ─────────── Telegram bot + Mini App (v3.4) ───────────
// The admin connects their own bot via Settings; we then:
//   • setMyCommands  (/start)
//   • setChatMenuButton → web_app button pointing at this panel
//   • setWebhook      → /panel/tgwebhook (secret-token guarded)
//   • validate initData (HMAC-SHA256, Telegram WebAppData spec) so the
//     admin can log into the panel from inside Telegram with NO password.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	tgTokenRe = regexp.MustCompile(`^[0-9]{6,12}:[A-Za-z0-9_\-]{30,60}$`)
	tgIDRe    = regexp.MustCompile(`^[0-9]{5,20}$`)
)

var tgHTTP = &http.Client{Timeout: 15 * time.Second}

// tgBotAPI calls a Bot-API method; returns the "result" object on success.
func tgBotAPI(token, method string, payload map[string]any) (map[string]any, error) {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req, err := http.NewRequest("POST", "https://api.telegram.org/bot"+token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DeepNetwork/"+Version)
	resp, err := tgHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("اتصال به تلگرام برقرار نشد")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil, fmt.Errorf("پاسخ نامعتبر از تلگرام")
	}
	if ok, _ := out["ok"].(bool); !ok {
		desc, _ := out["description"].(string)
		if desc == "" {
			desc = "خطای نامشخص"
		}
		return nil, fmt.Errorf("%s", desc)
	}
	res, _ := out["result"].(map[string]any)
	if res == nil {
		res = map[string]any{}
	}
	return res, nil
}

// panelBaseURL derives the public https base of this deployment from the
// incoming request (Lucity edge sends the real host + proto).
func panelBaseURL(r *http.Request) string {
	proto := "https"
	if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p == "http" {
		proto = "http"
	}
	return proto + "://" + requestHost(r)
}

// validateTGInitData verifies Telegram Mini-App initData per the official
// WebAppData spec and returns the Telegram user id on success.
func validateTGInitData(initData, botToken string) (int64, bool) {
	if initData == "" || botToken == "" {
		return 0, false
	}
	vals, err := url.ParseQuery(initData)
	if err != nil {
		return 0, false
	}
	provided := strings.ToLower(vals.Get("hash"))
	if provided == "" {
		return 0, false
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		if k == "hash" || k == "signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var dcs strings.Builder
	for i, k := range keys {
		if i > 0 {
			dcs.WriteByte('\n')
		}
		dcs.WriteString(k + "=" + vals.Get(k))
	}
	secretKeyMac := hmac.New(sha256.New, []byte("WebAppData"))
	secretKeyMac.Write([]byte(botToken))
	secretKey := secretKeyMac.Sum(nil)
	hashMac := hmac.New(sha256.New, secretKey)
	hashMac.Write([]byte(dcs.String()))
	sum := hex.EncodeToString(hashMac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sum), []byte(provided)) != 1 {
		return 0, false
	}
	// replay window: initData is minted fresh on every Mini-App open
	if ad, _ := strconv.ParseInt(vals.Get("auth_date"), 10, 64); ad > 0 {
		if time.Now().Unix()-ad > 86400 {
			return 0, false
		}
	}
	var u struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal([]byte(vals.Get("user")), &u) != nil || u.ID == 0 {
		return 0, false
	}
	return u.ID, true
}

// handleTelegramConnect: POST /panel/api/telegram {token, admin_id}
func handleTelegramConnect(w http.ResponseWriter, r *http.Request) {
	d := readJSONBody(r)
	token := strings.TrimSpace(jstr(d, "token"))
	adminID := strings.TrimSpace(jstr(d, "admin_id"))
	if token == "" || adminID == "" {
		sendJSON(w, 400, map[string]any{"error": "توکن ربات و شناسه عددی تلگرام هر دو لازم است"})
		return
	}
	if len(token) > 80 || !tgTokenRe.MatchString(token) {
		sendJSON(w, 400, map[string]any{"error": "قالب توکن معتبر نیست — از @BotFather کپی کنید (مثال: 123456789:AAF...)"})
		return
	}
	if !tgIDRe.MatchString(adminID) {
		sendJSON(w, 400, map[string]any{"error": "شناسه تلگرام باید عدد باشد — از @userinfobot بگیرید"})
		return
	}
	me, err := tgBotAPI(token, "getMe", nil)
	if err != nil {
		sendJSON(w, 400, map[string]any{"error": "توکن قبول نشد: " + err.Error()})
		return
	}
	username, _ := me["username"].(string)
	firstName, _ := me["first_name"].(string)
	if username == "" {
		sendJSON(w, 400, map[string]any{"error": "این توکن متعلق به یک ربات معتبر نیست"})
		return
	}
	base := panelBaseURL(r)
	if !strings.HasPrefix(base, "https://") {
		sendJSON(w, 400, map[string]any{"error": "آدرس پنل باید HTTPS باشد — روی Lucity خودکار است"})
		return
	}
	if _, err := tgBotAPI(token, "setMyCommands", map[string]any{
		"commands": []map[string]string{{"command": "start", "description": "باز کردن پنل"}},
	}); err != nil {
		sendJSON(w, 400, map[string]any{"error": "ثبت دستور /start ناموفق بود: " + err.Error()})
		return
	}
	if _, err := tgBotAPI(token, "setChatMenuButton", map[string]any{
		"menu_button": map[string]any{"type": "web_app", "text": "پنل DEEP NETWORK", "url": base + "/panel"},
	}); err != nil {
		sendJSON(w, 400, map[string]any{"error": "ساخت دکمه منوی ربات ناموفق بود: " + err.Error()})
		return
	}
	secret := randHex(16)
	if _, err := tgBotAPI(token, "setWebhook", map[string]any{
		"url":                base + "/panel/tgwebhook",
		"secret_token":       secret,
		"allowed_updates":    []string{"message"},
		"drop_pending_updates": true,
	}); err != nil {
		sendJSON(w, 400, map[string]any{"error": "ثبت وب‌هوک ناموفق بود: " + err.Error()})
		return
	}
	stateMu.Lock()
	state.TGToken, state.TGAdminID = token, adminID
	state.TGBotUser, state.TGBotName, state.TGHookSecret = username, firstName, secret
	saveStateLocked()
	stateMu.Unlock()
	logf("telegram bot connected: @%s (mini app %s/panel)", username, base)
	sendJSON(w, 200, map[string]any{"ok": true, "bot_username": username})
}

// handleTelegramDisconnect: DELETE /panel/api/telegram
func handleTelegramDisconnect(w http.ResponseWriter, r *http.Request) {
	stateMu.RLock()
	token := state.TGToken
	stateMu.RUnlock()
	if token != "" {
		_, _ = tgBotAPI(token, "deleteWebhook", map[string]any{"drop_pending_updates": true})
	}
	stateMu.Lock()
	state.TGToken, state.TGAdminID, state.TGBotUser, state.TGBotName, state.TGHookSecret = "", "", "", "", ""
	saveStateLocked()
	stateMu.Unlock()
	sendJSON(w, 200, map[string]any{"ok": true})
}

// handleTelegramWebhook: POST /panel/tgwebhook (secret-token guarded, no session)
func handleTelegramWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	stateMu.RLock()
	token, secret := state.TGToken, state.TGHookSecret
	stateMu.RUnlock()
	if token == "" {
		sendJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	hdr := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
	if secret == "" || subtle.ConstantTimeCompare([]byte(hdr), []byte(secret)) != 1 {
		sendJSON(w, 403, map[string]any{"error": "forbidden"})
		return
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	var upd struct {
		Message *struct {
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
			Text string `json:"text"`
		} `json:"message"`
	}
	if json.Unmarshal(b, &upd) != nil || upd.Message == nil || upd.Message.Chat.ID == 0 {
		sendJSON(w, 200, map[string]any{"ok": true})
		return
	}
	base := panelBaseURL(r)
	_, _ = tgBotAPI(token, "sendMessage", map[string]any{
		"chat_id": upd.Message.Chat.ID,
		"text":    "برای باز کردن پنل DEEP NETWORK دکمه زیر را بزنید.",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]any{{
				{"text": "باز کردن پنل", "web_app": map[string]any{"url": base + "/panel"}},
			}},
		},
	})
	sendJSON(w, 200, map[string]any{"ok": true})
}
