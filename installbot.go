package main

// ─────────── Telegram install bot (enabled with the INSTALL_BOT_TOKEN variable) ───────────
//
// Anyone who wants their own DEEP NETWORK panel just messages this bot.
// Flow: /start → paste a Lucity API token (lucity_…) → the bot deploys the
// public ghcr.io image on the *requester's own* Lucity workspace (project +
// 10Gi volume at /data + service + domain + health check), then sends back
// the panel link with the admin username/password. No GitHub, no dashboard,
// no terminal needed on the requester side.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// tgAPIBase and panelURLScheme are vars so tests can point them at a mock.
	tgAPIBase        = "https://api.telegram.org"
	panelURLScheme   = "https"
	installPollDelay = 10 * time.Second // service-status poll interval during install

	installBotHTTP  = &http.Client{Timeout: 65 * time.Second}
	installBotToken string

	// poll-loop liveness (updated after EVERY getUpdates completion):
	// the watchdog retires and replaces a loop that has gone stale.
	ibotGen      atomic.Int64 // loop generation; a stale loop exits on mismatch
	ibotLastPoll atomic.Int64 // unix seconds of the last completed poll
)

const ibotStaleAfter = 150 * time.Second // no completed poll for this long → restart loop

const (
	ibotMaxConcurrent = 3                // global concurrent installs
	ibotMaxTries      = 3                // failed token exchanges before cooldown
	ibotCooldown      = 10 * time.Minute // cooldown after too many bad tokens
)

// ─────────── Telegram Bot-API layer (own client: long polling needs >30s) ───────────

// ibotCallRaw performs one Bot-API call and returns the RAW "result"
// field — which may be an object (getMe, sendMessage), an array
// (getUpdates) or a scalar (setMyCommands). Callers that expect an
// object should use ibotCall instead.
func ibotCallRaw(method string, payload map[string]any) (any, error) {
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	req, err := http.NewRequest("POST", tgAPIBase+"/bot"+installBotToken+"/"+method, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "DeepNetwork/"+Version)
	resp, err := installBotHTTP.Do(req)
	if err != nil {
		return nil, errors.New("اتصال به تلگرام برقرار نشد")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil, errors.New("پاسخ نامعتبر از تلگرام")
	}
	if ok, _ := out["ok"].(bool); !ok {
		desc, _ := out["description"].(string)
		if desc == "" {
			desc = "خطای نامشخص"
		}
		return nil, errors.New(desc)
	}
	return out["result"], nil
}

// ibotCall is ibotCallRaw for endpoints whose result is a JSON object.
func ibotCall(method string, payload map[string]any) (map[string]any, error) {
	res, err := ibotCallRaw(method, payload)
	if err != nil {
		return nil, err
	}
	m, _ := res.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

func ibotSend(chat int64, text string) int64 {
	res, err := ibotCall("sendMessage", map[string]any{"chat_id": chat, "text": text})
	if err != nil {
		logf("install bot: sendMessage: %v", err)
		return 0
	}
	id, _ := res["message_id"].(float64)
	return int64(id)
}

func ibotEdit(chat, msgID int64, text string) {
	if msgID == 0 {
		return
	}
	_, err := ibotCall("editMessageText", map[string]any{"chat_id": chat, "message_id": msgID, "text": text})
	if err != nil && !strings.Contains(err.Error(), "not modified") {
		logf("install bot: editMessageText: %v", err)
	}
}

func ibotDelete(chat, msgID int64) {
	if msgID == 0 {
		return
	}
	_, _ = ibotCall("deleteMessage", map[string]any{"chat_id": chat, "message_id": msgID})
}

// ─────────── update types ───────────

type tgChatT struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type tgMessageT struct {
	MessageID int64 `json:"message_id"`
	From      *struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"from"`
	Chat *tgChatT `json:"chat"`
	Text string   `json:"text"`
}

type tgUpdateT struct {
	UpdateID int64       `json:"update_id"`
	Message  *tgMessageT `json:"message"`
}

// ─────────── per-chat session ───────────

type ibotSession struct {
	mu         sync.Mutex
	installing bool
	statusMsg  int64
	tries      int
	lastTry    time.Time
	started    time.Time
}

var (
	ibotMu   sync.Mutex
	ibotSess = map[int64]*ibotSession{}
)

func ibotSessGet(chat int64) *ibotSession {
	ibotMu.Lock()
	defer ibotMu.Unlock()
	s := ibotSess[chat]
	if s == nil {
		s = &ibotSession{}
		ibotSess[chat] = s
	}
	return s
}

// ─────────── polling loop ───────────

func installBotLoop(token string) {
	gen := ibotGen.Load()
	installBotToken = token
	// long polling cannot coexist with a webhook — clear any leftover first
	if _, err := ibotCall("deleteWebhook", map[string]any{"drop_pending_updates": false}); err != nil {
		logf("install bot: deleteWebhook: %v", err)
	}
	res, err := ibotCall("getMe", nil)
	if err != nil {
		logf("install bot: getMe FAILED — bot not started: %v", err)
		return
	}
	un, _ := res["username"].(string)
	logf("install bot: @%s online — paste-token-to-install flow ready", un)
	if _, err := ibotCall("setMyCommands", map[string]any{"commands": []map[string]string{
		{"command": "start", "description": "نصب پنل DEEP NETWORK"},
		{"command": "cancel", "description": "لغو نصب در جریان"},
		{"command": "help", "description": "راهنما"},
	}}); err != nil {
		logf("install bot: setMyCommands: %v", err)
	}

	var offset int64
	ibotLastPoll.Store(time.Now().Unix())
	for {
		if ibotGen.Load() != gen {
			logf("install bot: loop gen %d retired (current %d) — watchdog replaced it", gen, ibotGen.Load())
			return
		}
		ups, maxID, err := ibotGetUpdates(offset, 30)
		ibotLastPoll.Store(time.Now().Unix())
		if err != nil {
			logf("install bot: getUpdates: %v", err)
			if strings.Contains(err.Error(), "Conflict") {
				// a webhook re-appeared (or an older stuck poll) — clear and keep polling
				_, _ = ibotCall("deleteWebhook", map[string]any{"drop_pending_updates": false})
			}
			time.Sleep(5 * time.Second)
			continue
		}
		// advance the offset past EVERY returned update, even ones that failed
		// to parse — otherwise a single malformed update could wedge the queue.
		if maxID >= offset {
			offset = maxID + 1
		}
		for _, u := range ups {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			ibotProcessSafe(u)
		}
	}
}

// ibotWatchdog replaces the poll loop if it ever stops completing polls
// (stuck call, killed goroutine, …). Old loops retire themselves via the
// generation counter on their next iteration.
func ibotWatchdog(token string) {
	for {
		time.Sleep(60 * time.Second)
		last := time.Unix(ibotLastPoll.Load(), 0)
		if time.Since(last) < ibotStaleAfter {
			continue
		}
		ibotGen.Add(1)
		ibotLastPoll.Store(time.Now().Unix())
		slog.Warn("install bot: poll loop stale, restarting", "last_poll", last.Format(time.RFC3339))
		logf("install bot: watchdog — poll loop stale since %s, restarting it", last.Format(time.RFC3339))
		go installBotLoop(token)
	}
}

// ibotProcessSafe runs one update with panic isolation so a single bad
// update can never take the whole poll loop down.
func ibotProcessSafe(u tgUpdateT) {
	defer func() {
		if r := recover(); r != nil {
			logf("install bot: recovered from panic while handling update %d: %v", u.UpdateID, r)
		}
	}()
	ibotProcess(u)
}

func ibotGetUpdates(offset int64, timeout int) ([]tgUpdateT, int64, error) {
	// NOTE: the result of getUpdates is an ARRAY — ibotCallRaw (not ibotCall)
	// must be used here, or every fetched update would be silently dropped.
	res, err := ibotCallRaw("getUpdates", map[string]any{
		"offset":          offset,
		"timeout":         timeout,
		"allowed_updates": []string{"message"},
	})
	if err != nil {
		return nil, 0, err
	}
	raw, _ := res.([]any)
	var out []tgUpdateT
	var maxID int64
	for _, r := range raw {
		// take update_id straight from the raw map so the offset can advance
		// even when the rest of the update fails to parse
		if m, _ := r.(map[string]any); m != nil {
			if f, _ := m["update_id"].(float64); int64(f) > maxID {
				maxID = int64(f)
			}
		}
		b, _ := json.Marshal(r)
		var u tgUpdateT
		if json.Unmarshal(b, &u) == nil {
			out = append(out, u)
		}
	}
	return out, maxID, nil
}

// ─────────── update dispatch ───────────

func ibotProcess(u tgUpdateT) {
	if u.Message == nil || u.Message.Chat == nil {
		return
	}
	chat := u.Message.Chat
	if chat.Type != "" && chat.Type != "private" {
		return // group chats stay silent
	}
	text := strings.TrimSpace(u.Message.Text)
	if text == "" {
		return
	}
	fields := strings.Fields(text)
	cmd := fields[0]
	if i := strings.IndexByte(cmd, '@'); i > 0 { // "/start@mybot" → "/start"
		cmd = cmd[:i]
	}
	switch cmd {
	case "/start", "/install":
		ibotCmdStart(chat.ID)
	case "/cancel":
		ibotCmdCancel(chat.ID)
	case "/help":
		ibotCmdHelp(chat.ID)
	default:
		if strings.HasPrefix(text, "lucity_") {
			ibotOnToken(chat.ID, u.Message.MessageID, text)
			return
		}
		ibotSend(chat.ID, "سلام! برای نصب پنل DEEP NETWORK، دستور /start را بفرست.")
	}
}

// ─────────── commands ───────────

func ibotCmdStart(chat int64) {
	ibotSend(chat, "🐺 DEEP NETWORK — نصب خودکار پنل\n\n"+
		"این ربات یک پنل اختصاصی DEEP NETWORK روی ابر رایگان Lucity برایت نصب می‌کند و آدرس + یوزرنیم + پسورد را همین‌جا می‌فرستد.\n\n"+
		"قدم‌های نصب:\n"+
		"1. اگر اکانت Lucity نداری، در lucity.cloud ثبت‌نام کن (رایگان).\n"+
		"2. در داشبورد Lucity یک API Token بساز: Settings ← API Tokens ← Create Token.\n"+
		"3. همان توکن (که با lucity_ شروع می‌شود) را همین‌جا بفرست.\n\n"+
		"نصب کامل معمولاً 3 تا 10 دقیقه طول می‌کشد؛ بعد از آن لینک پنل و اطلاعات ورود برایت ارسال می‌شود.\n\n"+
		"/cancel — لغو نصب\n/help — راهنما")
}

func ibotCmdHelp(chat int64) {
	ibotSend(chat, "📖 راهنمای ربات نصب DEEP NETWORK\n\n"+
		"/start — شروع نصب پنل\n"+
		"/cancel — لغو نصب در جریان\n\n"+
		"پرسش‌های متداول:\n"+
		"• نصب رایگان است؟ بله — پنل روی اکانت رایگان خودت در Lucity نصب می‌شود.\n"+
		"• پسورد کجاست؟ بعد از اتمام نصب، همین‌جا برایت ارسال می‌شود.\n"+
		"• آدرس پنل را گم کردی؟ همان لینکی است که ربات فرستاده؛ از داشبورد Lucity هم قابل مشاهده است.\n"+
		"• برای امنیت، بعد از نصب توکن Lucity خودت را از داشبورد حذف (Revoke) کن.")
}

func ibotCmdCancel(chat int64) {
	s := ibotSessGet(chat)
	s.mu.Lock()
	busy := s.installing
	s.mu.Unlock()
	if busy {
		// Lucity deployments cannot be aborted mid-flight; faking a cancel
		// would strand a panel with an unknown password. Be honest instead.
		ibotSend(chat, "⚠️ نصب در جریان است و قابل توقف فوری نیست.\n\n"+
			"سرویس روی Lucity کامل می‌شود و اطلاعات ورود را همین‌جا می‌فرستم. "+
			"اگر واقعاً نمی‌خواهی، بعد از دریافت اطلاعات، سرویس deep-network را از داشبورد Lucity حذف کن.")
		return
	}
	ibotSend(chat, "نصبی در جریان نیست. برای شروع /start را بفرست.")
}

// ─────────── token intake → install ───────────

func ibotOnToken(chat, msgID int64, raw string) {
	s := ibotSessGet(chat)
	s.mu.Lock()
	if s.installing {
		s.mu.Unlock()
		ibotSend(chat, "⏳ نصب تو هنوز در جریان است. صبر کن تا تمام شود یا /cancel را بفرست.")
		return
	}
	if s.tries >= ibotMaxTries && time.Since(s.lastTry) < ibotCooldown {
		s.mu.Unlock()
		ibotSend(chat, "⏳ چند تلاش ناموفق پشت‌سرهم. حدود ۱۰ دقیقه صبر کن و بعد دوباره توکن بفرست.")
		return
	}
	s.lastTry = time.Now()
	s.installing = true // claim the slot synchronously — two quick tokens must not double-install
	s.mu.Unlock()

	if installsBusy() >= ibotMaxConcurrent {
		s.mu.Lock()
		s.installing = false
		s.mu.Unlock()
		ibotSend(chat, "⏳ الان چند نصب دیگر در جریان است (ظرفیت ربات پر است). چند دقیقه بعد دوباره همان توکن را بفرست.")
		return
	}

	// the token itself must not linger in the chat history
	ibotDelete(chat, msgID)
	status := ibotSend(chat, "🔑 توکن دریافت شد و پیام حاوی آن برای امنیت حذف شد.\n\nدر حال بررسی توکن…")

	lc, err := lucityExchange(raw)
	if err != nil {
		s.mu.Lock()
		s.tries++
		s.installing = false
		s.mu.Unlock()
		ibotEdit(chat, status, "❌ "+err.Error()+"\n\n"+
			"یک توکن معتبر بفرست (از داشبورد Lucity: Settings ← API Tokens)، یا /cancel برای رها کردن.")
		return
	}
	s.mu.Lock()
	s.tries = 0
	s.mu.Unlock()

	go ibotRunInstall(chat, status, lc)
}

// ibotRunInstall runs the full deployment and reports progress by editing
// the status message. Runs in its own goroutine; the "installing" slot was
// already claimed synchronously by ibotOnToken.
func ibotRunInstall(chat, status int64, lc *lucityClient) {
	s := ibotSessGet(chat)
	defer func() {
		s.mu.Lock()
		s.installing = false
		s.mu.Unlock()
	}()

	installsInc(1)
	defer installsInc(-1)

	labels := map[int]string{
		1: "بررسی اکانت Lucity",
		2: "ساخت پروژه و دیسک",
		3: "ساخت سرویس پنل",
		4: "دریافت آدرس پنل",
		5: "راه‌اندازی سرور (چند دقیقه طول می‌کشد)",
		6: "بررسی نهایی و تحویل",
	}
	pass := randomPassword()
	res, err := installPanel(lc, pass, func(step int, note string) {
		txt := "🚀 نصب DEEP NETWORK در جریان است.\n\n" +
			"مرحله " + strconv.Itoa(step) + " از 6: " + labels[step] + "…\n\n" +
			"این پیام خودش به‌روز می‌شود؛ صبور باش 🙏"
		if note != "" {
			txt += "\n\n" + note
		}
		ibotEdit(chat, status, txt)
	})
	if err != nil {
		if errors.Is(err, errAlreadyInstalled) {
			ibotEdit(chat, status, "ℹ️ روی این اکانت Lucity از قبل سرویس «deep-network» وجود دارد.\n\n"+
				"• اگر همان پنل قدیمی را می‌خواهی: آدرسش را از داشبورد Lucity ببین.\n"+
				"• اگر می‌خواهی از نو نصب شود: اول سرویس deep-network را از داشبورد Lucity حذف کن و دوباره توکن را بفرست.")
			return
		}
		ibotEdit(chat, status, "❌ نصب انجام نشد.\n\n"+err.Error()+"\n\n"+
			"دوباره تلاش کن — یک توکن معتبر Lucity بفرست. اگر مشکل ادامه داشت، چند دقیقه بعد /start را بفرست.")
		return
	}

	// double-check the credentials against the fresh panel before delivery
	loginOK := verifyPanelLogin(res.PanelURL, res.AdminUser, res.AdminPass)

	final := "✅ پنل DEEP NETWORK آماده شد!\n\n" +
		"🔗 آدرس پنل:\n" + res.PanelURL + "\n\n" +
		"👤 یوزرنیم: " + res.AdminUser + "\n" +
		"🔑 پسورد: " + res.AdminPass + "\n\n" +
		"نکته‌ها:\n" +
		"• این تنها جایی است که پسورد نشان داده می‌شود — همین پیام را Forward یا Save کن.\n" +
		"• بعد از ورود، از «تنظیمات» پسورد را عوض کن.\n" +
		"• برای کم‌کردن پینگ: در پنل «اسکنر IP» را اجرا کن و نزدیک‌ترین لبه (ترکیه/آذربایجان/عراق) را اعمال کن.\n" +
		"• می‌توانی پنل را به‌عنوان مینی‌اپ تلگرام هم وصل کنی: تنظیمات ← ربات تلگرام.\n" +
		"• امنیت: توکن Lucity که فرستادی دیگر لازم نیست — از داشبورد Lucity حذفش کن (Revoke)."
	if !loginOK {
		final += "\n\n⚠️ سرور همین حالا بالا آمده؛ اگر ورود کار نکرد، یک دقیقه بعد دوباره امتحان کن."
	}
	ibotEdit(chat, status, "✅ نصب کامل شد — اطلاعات ورود در پیام بعدی. 🐺")
	ibotSend(chat, final)
}
