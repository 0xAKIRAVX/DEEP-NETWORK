package main

import (
        "bytes"
        "encoding/base64"
        "image"
        "image/color"
        _ "image/gif"
        _ "image/jpeg"
        "image/png"
        "io"
        "net/http"
        "os"
        "strings"
        "time"
)

// ─────────── admin profile picture (avatar) ───────────
// Uploaded images are center-cropped, downscaled to 256×256 PNG and stored in
// the persistent data dir (survives redeploys on the /data volume).

func avatarPath() string { return dataDir() + "/avatar.png" }

// serveAvatar GET /panel/avatar.png — public (also shown on the login screen).
// Falls back to the embedded default avatar when none was uploaded.
func serveAvatar(w http.ResponseWriter, r *http.Request) {
        if b, err := os.ReadFile(avatarPath()); err == nil && len(b) > 0 {
                w.Header().Set("Content-Type", "image/png")
                w.Header().Set("Cache-Control", "public, max-age=120")
                w.Header().Set("Content-Length", itoa(len(b)))
                w.WriteHeader(200)
                _, _ = w.Write(b)
                return
        }
        b, err := webFS.ReadFile("web/assets/img/avatar.jpg")
        if err != nil {
                http.NotFound(w, r)
                return
        }
        w.Header().Set("Content-Type", "image/jpeg")
        w.Header().Set("Cache-Control", "public, max-age=86400")
        w.Header().Set("Content-Length", itoa(len(b)))
        w.WriteHeader(200)
        _, _ = w.Write(b)
}

// handleAvatarUpload POST /panel/api/avatar — multipart "file" field or JSON {"data": "<base64|dataURL>"}.
func handleAvatarUpload(w http.ResponseWriter, r *http.Request) {
        var data []byte
        ct := r.Header.Get("Content-Type")
        if strings.HasPrefix(ct, "multipart/form-data") {
                if err := r.ParseMultipartForm(8 << 20); err != nil {
                        sendJSON(w, 400, map[string]any{"error": "حجم فایل بیش از حد مجاز است (حداکثر ۸ مگابایت)"})
                        return
                }
                f, _, err := r.FormFile("file")
                if err != nil {
                        sendJSON(w, 400, map[string]any{"error": "فایلی انتخاب نشده است"})
                        return
                }
                defer f.Close()
                b, err := io.ReadAll(io.LimitReader(f, 8<<20))
                if err != nil || len(b) == 0 {
                        sendJSON(w, 400, map[string]any{"error": "خواندن فایل ممکن نشد"})
                        return
                }
                data = b
        } else {
                d := readJSONBody(r)
                b64 := jstr(d, "data")
                if i := strings.Index(b64, ";base64,"); i >= 0 {
                        b64 = b64[i+8:]
                } else if strings.HasPrefix(b64, "base64,") {
                        b64 = b64[7:]
                }
                b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
                if err != nil || len(b) == 0 || len(b) > 8<<20 {
                        sendJSON(w, 400, map[string]any{"error": "تصویر نامعتبر است"})
                        return
                }
                data = b
        }

        img, _, err := image.Decode(bytes.NewReader(data))
        if err != nil {
                sendJSON(w, 400, map[string]any{"error": "فقط تصویر PNG / JPG / GIF پشتیبانی می‌شود"})
                return
        }

        const target = 256
        bd := img.Bounds()
        side := bd.Dx()
        if dy := bd.Dy(); dy < side {
                side = dy
        }
        if side < 1 {
                sendJSON(w, 400, map[string]any{"error": "تصویر نامعتبر است"})
                return
        }
        cx, cy := bd.Min.X+bd.Dx()/2, bd.Min.Y+bd.Dy()/2
        x0, y0 := cx-side/2, cy-side/2

        // box-average resample (square center-crop → 256×256): smooth and fast enough
        dst := image.NewRGBA(image.Rect(0, 0, target, target))
        for y := 0; y < target; y++ {
                sy0 := y0 + y*side/target
                sy1 := y0 + (y+1)*side/target
                if sy1 <= sy0 {
                        sy1 = sy0 + 1
                }
                for x := 0; x < target; x++ {
                        sx0 := x0 + x*side/target
                        sx1 := x0 + (x+1)*side/target
                        if sx1 <= sx0 {
                                sx1 = sx0 + 1
                        }
                        var rs, gs, bs, as, n uint64
                        for sy := sy0; sy < sy1; sy++ {
                                for sx := sx0; sx < sx1; sx++ {
                                        pr, pg, pb, pa := img.At(sx, sy).RGBA()
                                        rs += uint64(pr)
                                        gs += uint64(pg)
                                        bs += uint64(pb)
                                        as += uint64(pa)
                                        n++
                                }
                        }
                        if n == 0 {
                                n = 1
                        }
                        a := uint8(as / n >> 8)
                        if a == 0 {
                                dst.SetRGBA(x, y, color.RGBA{})
                                continue
                        }
                        dst.SetRGBA(x, y, color.RGBA{R: uint8(rs / n >> 8), G: uint8(gs / n >> 8), B: uint8(bs / n >> 8), A: a})
                }
        }

        var buf bytes.Buffer
        if err := png.Encode(&buf, dst); err != nil {
                sendJSON(w, 500, map[string]any{"error": "پردازش تصویر ممکن نشد"})
                return
        }
        if err := os.WriteFile(avatarPath(), buf.Bytes(), 0o644); err != nil {
                sendJSON(w, 500, map[string]any{"error": "ذخیره تصویر ممکن نشد (دیسک پر است؟)"})
                return
        }
        sendJSON(w, 200, map[string]any{"ok": true, "v": time.Now().Unix()})
}

// handleAvatarDelete POST /panel/api/avatar/delete — reset to the default avatar.
func handleAvatarDelete(w http.ResponseWriter, r *http.Request) {
        _ = os.Remove(avatarPath())
        sendJSON(w, 200, map[string]any{"ok": true})
}
