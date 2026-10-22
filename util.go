package main

import (
        "archive/zip"
        "bytes"
        "compress/gzip"
        "crypto/rand"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "syscall"
)

// ─────────── small shared helpers ───────────

// sendJSONGz marshals obj and writes it gzip-compressed when the client
// accepts it and the body is large enough to be worth it (v3.3: stats/state
// payloads are polled every few seconds — 5-6KB raw ≈ 1.3KB gzipped, which
// matters a lot on filtered mobile links where every byte adds latency).
func sendJSONGz(r *http.Request, w http.ResponseWriter, code int, obj any) {
        b, _ := json.Marshal(obj)
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        if len(b) > 512 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
                var buf bytes.Buffer
                gz := gzip.NewWriter(&buf)
                _, _ = gz.Write(b)
                _ = gz.Close()
                if buf.Len() < len(b) {
                        w.Header().Set("Content-Encoding", "gzip")
                        w.Header().Set("Content-Length", itoa(buf.Len()))
                        w.WriteHeader(code)
                        _, _ = w.Write(buf.Bytes())
                        return
                }
        }
        w.Header().Set("Content-Length", itoa(len(b)))
        w.WriteHeader(code)
        _, _ = w.Write(b)
}

func fmtSscan(s string, n *int) (int, error) {
        return fmt.Sscan(s, n)
}

func randRead(b []byte) {
        if _, err := rand.Read(b); err != nil {
                for i := range b {
                        b[i] = byte(i * 7)
                }
        }
}

// pyQuote mirrors Python's urllib.parse.quote(s, safe=""): percent-encode
// everything except unreserved characters; space becomes %20 (not +).
func pyQuote(s string) string {
        const hexd = "0123456789ABCDEF"
        var b []byte
        for i := 0; i < len(s); i++ {
                c := s[i]
                if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '-' || c == '_' || c == '.' || c == '~' {
                        b = append(b, c)
                } else {
                        b = append(b, '%', hexd[c>>4], hexd[c&0xF])
                }
        }
        return string(b)
}

func exeAbs() (string, error) {
        return os.Executable()
}

func dirOf(p string) string {
        i := len(p) - 1
        for i >= 0 && p[i] != '/' {
                i--
        }
        if i <= 0 {
                return "."
        }
        return p[:i]
}

func statFile(p string) (os.FileInfo, error) {
        return os.Stat(p)
}

// downloadUnzip fetches a zip from url and extracts `name` into dest (xray bootstrap).
func downloadUnzip(url, dest, name string) error {
        resp, err := httpClientGet(url)
        if err != nil {
                return err
        }
        defer resp.Body.Close()
        if resp.StatusCode != 200 {
                return fmt.Errorf("HTTP %d", resp.StatusCode)
        }
        data, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
        if err != nil {
                return err
        }
        zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
        if err != nil {
                return err
        }
        for _, f := range zr.File {
                base := filepath.Base(f.Name)
                if base == name {
                        rc, err := f.Open()
                        if err != nil {
                                return err
                        }
                        defer rc.Close()
                        if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
                                return err
                        }
                        out, err := os.Create(dest)
                        if err != nil {
                                return err
                        }
                        defer out.Close()
                        _, err = io.Copy(out, rc)
                        return err
                }
        }
        return fmt.Errorf("%s missing in archive", name)
}

func termSignal() syscall.Signal {
        return syscall.SIGTERM
}
