# DEEP NETWORK

<div dir="rtl">

**DEEP NETWORK** — پنل مدیریت اشتراک VLESS/VMess/Trojan روی Lucity، بازنویسی کامل با **Go + Rust** (نسخه ۳).

پنل با ظاهر سینمایی نقره‌ای/مشکی، کره‌ی زمین چرخان با داده‌ی واقعی، نمودار پهنای‌باند زنده، اسکنر IP با هسته‌ی Rust و تنظیمات بهینه‌ی اپراتورهای ایران.

</div>

---

## معماری (Go + Rust)

| بخش | زبان | نقش |
|---|---|---|
| `main.go, server.go, api.go, ...` | **Go** | وب‌سرور واحد: پنل + API + سابسکریپشن + پراکسی تونل‌ها (nginx حذف شد) |
| `xray.go` | Go | ساخت کانفیگ و نظارت بر Xray-core (زیرپروسه) |
| `rust-probe/` → `bin/deep-probe` | **Rust** | پروبر چندنخی TCP + TLS ClientHello برای اسکنر IP و لبه‌های CDN |
| `web/` | HTML/CSS/JS | رابط کاربری (embed داخل باینری Go) |

- **بدون nginx** — باینری Go خودش روی `$PORT` گوش می‌دهد و مسیرهای `ws / xhttp / httpupgrade / vmess / trojan / اینباندهای سفارشی` را به Xray پراکسی می‌کند (شامل gRPC با h2c).
- **بدون Python** — بوت سریع، مصرف حافظه‌ی کم (~۲۰MB)، باینری استاتیک.
- پشتیبانی **h2c** برای gRPC از لبه‌ی Lucity.

## استقرار روی Lucity

1. این ریپو را به سرویس Lucity وصل کنید (سورس: `0xAKIRAVX/DEEP-NETWORK`).
2. Railpack خودش Go را تشخیص می‌دهد (`go.mod`) و `./out` را می‌سازد؛ مرحله‌ی `xray` در `railpack.json` هسته‌ی Xray را دانلود می‌کند.
3. متغیرهای محیطی پیشنهادی:

| متغیر | توضیح |
|---|---|
| `DOMAIN` | دامنه سرویس (`xxx.lucity.app`) — برای لینک‌ها و اسکنر CDN |
| `ADMIN_PASSWORD` | رمز ورود پنل (اگر ست نشود، خودکار ساخته و در لاگ دیپلوی چاپ می‌شود) |
| `UUID` / `SECRET` | ثابت‌نگه‌داشتن شناسه‌ها و توکن‌ها بین دیپلوی‌ها |
| `WS_PATH` … `TROJAN_PATH` | مسیرهای دلخواه ترنسپورت‌ها |

4. **حتماً یک Volume روی `/data` سوار کنید** تا کاربران/لینک‌ها بعد از دیپلوی از بین نروند.

> صفحه‌ی پنل: `https://<domain>/panel` — لینک اشتراک هر کاربر: `/sub/<token>`

## بهینه‌سازی برای ایران

- **SNI تصادفی**: هر لینک روی زیردامنه‌ی تصادفی `*.lucity.app` ساخته می‌شود تا فیلتر SNI دور بخورد (بدون هزینه‌ی پینگ).
- **پروفایل اپراتور** (ایرانسل / همراه‌اول / رایتل / شاتل / مبین‌نت / پارس‌آنلاین / مخابرات / آسیاتک): فرگمنت TLS و اثر انگشت مرورگر بهینه‌ی هر اپراتور، به‌صورت خودکار با تشخیص اپراتور شما (`/panel/api/whoami`).
- **اسکنر IP**: لبه‌های bunny.net (CDN خود Lucity) با Rust در چند ثانیه بررسی می‌شوند؛ نزدیک‌ترین لبه (ترکیه/آذربایجان/عراق) کم‌ترین پینگ را از ایران دارد — با یک کلیک روی همه‌ی کانفیگ‌ها اعمال می‌شود.
- **کانفیگ کلاینت بهینه**: `sockopt.tcpNoDelay + tcpFastOpen + keepalive`، مسیر مستقیم دامنه‌های ایرانی، بلاک تبلیغات و QUIC.

## توسعه

```bash
# Rust prober (استاتیک)
cd rust-probe && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/deep-probe ../bin/

# Go
go build -o out .

# تست E2E (34 مورد)
bash scripts/test_e2e_boot.sh

# یا همه‌ی این‌ها با یک دستور (فرمت + تحلیل ایستا + تست)
make check
```

## ابزارهای خط فرمان (`tools/`)

| ابزار | زبان | کاربرد |
|---|---|---|
| `tools/lucity_status.py` | Python | وضعیت لحظه‌ای سرویس روی Lucity (GraphQL + احراز هویت توکن) |
| `tools/rollout_retry.py` | Python | کمپین تکرار rollout برای گرفتن ظرفیت هنگام `UNSCHEDULABLE` |
| `tools/sub_e2e.py` | Python | اعتبارسنجی کامل ردیف‌های اشتراک `/sub/` مثل v2rayNG |
| `tools/c/familycheck.c` | C | ماشین‌حساب خانواده‌ی /16 برای بلاک‌لیست لبه‌ها (ارجاع standalone) |
| `tools/windows/panelcheck.ps1` | PowerShell | تست دسترسی پنل و اشتراک از ویندوز (شبکه‌ی خود کاربر) |
| `rust-probe/` | Rust | پروب تأخیر TCP/TLS چندنخی (باینری استاتیک) |

## لایسنس

MIT
