// Registration adapter follows Diniboy1123/usque api/cloudflare.go at
// 6aa03fc97d12848dce34eedbd187fb1077b5d1ea (MIT). Private keys stay in the browser.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed public/index.html public/app.js public/lib.mjs public/styles.css
var assets embed.FS

const sessionCookie = "warp_web_session"
const sessionDuration = 8 * time.Hour

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
func (s *service) matchesToken(r *http.Request) bool {
	a, b := sha256.Sum256([]byte(s.token)), sha256.Sum256([]byte(r.Header.Get("X-Registration-Token")))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

func (s *service) signSession(expiry string) string {
	mac := hmac.New(sha256.New, []byte(s.token))
	mac.Write([]byte(sessionCookie + ":" + expiry))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *service) hasSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	expiry, signature, ok := strings.Cut(c.Value, ".")
	timestamp, err := strconv.ParseInt(expiry, 10, 64)
	return ok && err == nil && timestamp > time.Now().Unix() &&
		hmac.Equal([]byte(signature), []byte(s.signSession(expiry)))
}

func (s *service) createSession(w http.ResponseWriter) {
	expiry := time.Now().Add(sessionDuration)
	value := strconv.FormatInt(expiry.Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: value + "." + s.signSession(value), Path: "/api/",
		Expires: expiry, MaxAge: int(sessionDuration.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	respond(w, http.StatusOK, map[string]bool{"ok": true})
}

type licenseAccount struct {
	License     string `json:"license"`
	AccountType string `json:"account_type"`
	WarpPlus    bool   `json:"warp_plus"`
}

func (a licenseAccount) hasPlus() bool {
	switch strings.ToLower(strings.TrimSpace(a.AccountType)) {
	case "plus", "warp+", "premium", "unlimited", "warp_plus", "warp_plus_unlimited":
		return true
	default:
		return a.WarpPlus
	}
}
func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/api/health" && r.Method == "GET" {
		respond(w, 200, map[string]any{"ok": true, "version": "0.3.0", "registrationEnabled": len(s.token) >= 16, "authorized": len(s.token) >= 16 && s.hasSession(r), "adapter": "usque-compatible"})
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
	switch r.URL.Path {
	case "/api/register", "/api/enroll", "/api/license", "/api/license/status", "/api/session":
	default:
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
	if !s.matchesToken(r) && (r.URL.Path == "/api/session" || !s.hasSession(r)) {
		fail(w, 401, "注册访问口令错误或会话已过期")
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
	if r.URL.Path == "/api/session" {
		s.createSession(w)
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
		token = input["token"]
		if !matches(`^[0-9a-zA-Z._:-]{4,128}$`, input["id"]) || len(token) < 8 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
			fail(w, 400, "设备 ID 或令牌无效")
			return
		}
		path += "/" + url.PathEscape(input["id"])
		switch r.URL.Path {
		case "/api/license", "/api/license/status":
			if !matches(`^[A-Za-z0-9]{8}(-[A-Za-z0-9]{8}){2}$`, input["license"]) {
				fail(w, 400, "许可证格式无效")
				return
			}
			path += "/account"
			method = http.MethodGet
			if r.URL.Path == "/api/license" {
				method = http.MethodPut
				body = map[string]any{"license": input["license"]}
			}
		case "/api/enroll":
			raw, e := base64.StdEncoding.DecodeString(input["public_key"])
			var valid bool
			if e == nil {
				if k, err := x509.ParsePKIXPublicKey(raw); err == nil {
					if ec, ok := k.(*ecdsa.PublicKey); ok && ec.Curve == elliptic.P256() {
						valid = true
					}
				}
			}
			if !valid || len([]rune(input["name"])) > 50 {
				fail(w, 400, "P-256 公钥或设备名称无效")
				return
			}
			method = http.MethodPatch
			body = map[string]any{"key": input["public_key"], "key_type": "secp256r1", "tunnel_type": "masque", "name": input["name"], "warp_enabled": true}
		}
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
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
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
		fail(w, 502, "Cloudflare 请求超时或无法连接，请稍后继续")
		return
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
	if err != nil || len(data) > 65536 {
		fail(w, 502, "上游响应过大或不完整")
		return
	}
	if res.StatusCode == 429 || (res.StatusCode >= 400 && bytes.Contains(data, []byte("1015"))) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "Cloudflare 限流，请至少等待 60 秒")
		return
	}
	if r.URL.Path == "/api/license" || r.URL.Path == "/api/license/status" {
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			licenseFailure(w, res.StatusCode, data, method)
			return
		}
		if method == http.MethodPut {
			respond(w, 200, map[string]bool{"ok": true})
			return
		}
		var account licenseAccount
		if json.Unmarshal(data, &account) != nil || (account.License == "" && account.AccountType == "") {
			fail(w, 502, "Cloudflare 未返回可识别的账户信息，暂时无法确认绑定")
			return
		}
		respond(w, 200, map[string]bool{
			"matched": account.License == input["license"], "plus": account.hasPlus(),
		})
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
func licenseFailure(w http.ResponseWriter, status int, data []byte, method string) {
	var reply struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(data, &reply)
	if method == http.MethodPut && status >= 400 && status < 500 {
		for _, detail := range reply.Errors {
			msg := strings.ToLower(detail.Message)
			if strings.Contains(msg, "device") && (strings.Contains(msg, "limit") || strings.Contains(msg, "too many") || strings.Contains(msg, "maximum")) {
				fail(w, 409, "此许可证的设备名额已满，请在 WARP 客户端管理旧设备后继续")
				return
			}
			if strings.Contains(msg, "license") && (strings.Contains(msg, "invalid") || strings.Contains(msg, "not found") || strings.Contains(msg, "expired")) {
				fail(w, 422, "Cloudflare 拒绝了该许可证，请核对密钥来源、有效期和大小写")
				return
			}
		}
		if status == 409 {
			fail(w, 409, "Cloudflare 报告设备绑定冲突，请检查许可证的设备列表")
			return
		}
	}
	fail(w, 502, fmt.Sprintf("Cloudflare 账户接口返回 HTTP %d，请检查设备或稍后继续", status))
}

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	s := &service{token: os.Getenv("REGISTRATION_TOKEN"), upstream: upstreamAPI, client: &http.Client{Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cooldown: 60 * time.Second}
	server := &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	certFile, keyFile := os.Getenv("TLS_CERT_FILE"), os.Getenv("TLS_KEY_FILE")
	if (certFile == "") != (keyFile == "") {
		log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
	}
	if certFile != "" {
		log.Printf("WARP MASQUE Web v0.3.0: https://%s", addr)
		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	}
	log.Printf("WARP MASQUE Web v0.3.0: http://%s", addr)
	log.Fatal(server.ListenAndServe())
}
