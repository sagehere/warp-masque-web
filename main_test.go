package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*service, *int) {
	t.Helper()
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid payload")
		}
		if body["private_key"] != nil {
			t.Error("private key leaked")
		}
		if r.Method == "PATCH" && (body["warp_enabled"] != true || r.Header.Get("Authorization") != "Bearer account-token") {
			t.Error("bad enrollment")
		}
		respond(w, 200, map[string]any{"id": "device-1234", "token": "account-token", "warp_enabled": true})
	}))
	t.Cleanup(up.Close)
	return &service{token: strings.Repeat("a", 32), upstream: up.URL, client: up.Client(), cooldown: time.Minute}, &calls
}
func request(s *service, path, body, token, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "http://localhost"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-WARP-Action", "personal-enrollment")
	r.Header.Set("X-Registration-Token", token)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func registration() string {
	return `{"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","serial_number":"0123456789abcdef","tos":"2026-11-16T00:00:00Z"}`
}
func TestAuthOriginAndBodyLimits(t *testing.T) {
	s, calls := fixture(t)
	for _, tc := range []struct {
		body, token, origin string
		status              int
	}{{registration(), "wrong", "", 401}, {registration(), s.token, "http://evil.example", 403}, {`{}`, s.token, "", 400}, {strings.Repeat("x", 9000), s.token, "", 400}, {registration() + `{}`, s.token, "", 400}} {
		w := request(s, "/api/register", tc.body, tc.token, tc.origin)
		if w.Code != tc.status {
			t.Fatalf("status %d expected %d", w.Code, tc.status)
		}
	}
	if *calls != 0 {
		t.Fatal("invalid request reached upstream")
	}
}
func TestRegisterCooldownAndEnrollment(t *testing.T) {
	s, calls := fixture(t)
	w := request(s, "/api/register", registration(), s.token, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if request(s, "/api/register", registration(), s.token, "").Code != 429 {
		t.Fatal("no cooldown")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	payload, _ := json.Marshal(map[string]string{"id": "device-1234", "token": "account-token", "public_key": base64.StdEncoding.EncodeToString(der), "name": "test"})
	if w = request(s, "/api/enroll", string(payload), s.token, ""); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if *calls != 2 {
		t.Fatal(*calls)
	}
}
func TestStaticSecretsAndHealth(t *testing.T) {
	s, _ := fixture(t)
	for _, path := range []string{"/", "/lib.mjs", "/api/health"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(s.token)) {
			t.Fatal(path)
		}
		if w.Header().Get("Cache-Control") == "" {
			t.Fatal("cache")
		}
	}
	for _, path := range []string{"/main.go", "/_worker.js", "/.env", "/api/unknown"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatal(path)
		}
	}
}
func TestUpstreamTimeoutAndRedaction(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, "TOP_SECRET_TOKEN")
	}))
	defer up.Close()
	s, _ := fixture(t)
	s.upstream = up.URL
	w := request(s, "/api/register", registration(), s.token, "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "TOP_SECRET") {
		t.Fatal(w.Body.String())
	}
}
