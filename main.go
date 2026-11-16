// Registration adapter follows Diniboy1123/usque api/cloudflare.go at
// 6aa03fc97d12848dce34eedbd187fb1077b5d1ea (MIT). Private keys stay in the browser.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed public/index.html public/app.js public/lib.mjs public/styles.css
var assets embed.FS

const upstreamAPI = "https://api.cloudflareclient.com/v0a4471"

var allowed = map[string]string{"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/lib.mjs": "lib.mjs", "/styles.css": "styles.css"}

type service struct {
	token    string
	client   *http.Client
	upstream string
	mu       sync.Mutex
	busy     bool
	next     time.Time
	cooldown time.Duration
}

func respond(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]any{"error": msg})
}
func matches(pattern, s string) bool { return regexp.MustCompile(pattern).MatchString(s) }
func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/api/health" && r.Method == "GET" {
		respond(w, 200, map[string]any{"ok": true, "version": "0.2.0", "registrationEnabled": len(s.token) >= 16, "adapter": "usque-compatible"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		name, ok := allowed[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.WriteHeader(405)
			return
		}
		data, _ := assets.ReadFile("public/" + name)
		if strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".mjs") {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		} else if strings.HasSuffix(name, ".css") {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		if r.Method == "GET" {
			_, _ = w.Write(data)
		}
		return
	}
	if r.URL.Path != "/api/register" && r.URL.Path != "/api/enroll" {
		fail(w, 404, "不存在的接口")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		fail(w, 405, "只支持 POST")
		return
	}
	// Same-origin defence does not trust arbitrary forwarded headers. Reverse proxies preserve Host.
	if origin := r.Header.Get("Origin"); origin != "" {
		u, e := url.Parse(origin)
		if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
			fail(w, 403, "跨站请求已拒绝")
			return
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		fail(w, 403, "跨站请求已拒绝")
		return
	}
	if len(s.token) < 16 {
		fail(w, 503, "服务端未设置至少 16 字符的 REGISTRATION_TOKEN")
		return
	}
	a, b := sha256.Sum256([]byte(s.token)), sha256.Sum256([]byte(r.Header.Get("X-Registration-Token")))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		fail(w, 401, "注册访问口令错误")
		return
	}
	if r.Header.Get("X-WARP-Action") != "personal-enrollment" {
		fail(w, 403, "缺少操作标识")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 400, "必须使用 application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var input map[string]string
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求格式错误或内容过大")
		return
	}
	var body map[string]any
	path := "/reg"
	method := "POST"
	token := ""
	if r.URL.Path == "/api/register" {
		key, e := base64.StdEncoding.DecodeString(input["key"])
		_, te := time.Parse(time.RFC3339Nano, input["tos"])
		if e != nil || len(key) != 32 || !matches(`^[a-fA-F0-9]{16}$`, input["serial_number"]) || te != nil {
			fail(w, 400, "临时公钥、序列或条款确认时间无效")
			return
		}
		body = map[string]any{"key": input["key"], "serial_number": input["serial_number"], "tos": input["tos"], "install_id": "", "fcm_token": "", "model": "PC", "os_version": "", "key_type": "curve25519", "tunnel_type": "wireguard", "locale": "en_US"}
	} else {
		raw, e := base64.StdEncoding.DecodeString(input["public_key"])
		var valid bool
		if e == nil {
			if k, err := x509.ParsePKIXPublicKey(raw); err == nil {
				if ec, ok := k.(*ecdsa.PublicKey); ok && ec.Curve == elliptic.P256() {
					valid = true
				}
			}
		}
		token = input["token"]
		if !matches(`^[0-9a-zA-Z._:-]{4,128}$`, input["id"]) || len(token) < 8 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") || !valid || len([]rune(input["name"])) > 50 {
			fail(w, 400, "设备 ID、令牌或 P-256 公钥无效")
			return
		}
		path += "/" + url.PathEscape(input["id"])
		method = "PATCH"
		body = map[string]any{"key": input["public_key"], "key_type": "secp256r1", "tunnel_type": "masque", "name": input["name"], "warp_enabled": true}
	}
	// Global bounded state prevents unbounded per-IP maps and proxy-IP ambiguity.
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		fail(w, 429, "注册服务忙，请稍后继续")
		return
	}
	if method == "POST" && time.Now().Before(s.next) {
		wait := max(1, int(time.Until(s.next).Seconds())+1)
		s.mu.Unlock()
		w.Header().Set("Retry-After", fmt.Sprint(wait))
		fail(w, 429, fmt.Sprintf("请等待 %d 秒后再注册", wait))
		return
	}
	s.busy = true
	if method == "POST" {
		s.next = time.Now().Add(s.cooldown)
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.busy = false; s.mu.Unlock() }()
	payload, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, s.upstream+path, bytes.NewReader(payload))
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("CF-Client-Version", "a-6.35-4471")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := s.client.Do(req)
	if err != nil {
		fail(w, 502, "无法连接 Cloudflare 注册接口或请求超时；请稍后重试，也可本地运行 usque 后导入")
		return
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 {
		fail(w, 502, "上游响应过大或不完整")
		return
	}
	if res.StatusCode == 429 || bytes.Contains(data, []byte("1015")) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "Cloudflare 限流，请至少等待 60 秒")
		return
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !json.Valid(data) {
		fail(w, 502, fmt.Sprintf("Cloudflare 注册接口返回 HTTP %d；请稍后重试或导入本地 usque 配置", res.StatusCode))
		return
	}
	// Never log bodies, keys, tokens, or upstream messages.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(data)
}
func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	s := &service{token: os.Getenv("REGISTRATION_TOKEN"), upstream: upstreamAPI, client: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cooldown: 60 * time.Second}
	server := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("WARP MASQUE Web v0.2.0: http://%s", addr)
	log.Fatal(server.ListenAndServe())
}
