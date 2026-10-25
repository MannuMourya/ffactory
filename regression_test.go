package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clientFor(t *testing.T, cfg *Config) *httpClient {
	t.Helper()
	c, err := newClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCredentialScope(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, name := range []string{"Authorization", "X-Api-Key", "Cookie"} {
			if got := r.Header.Get(name); got != "" {
				t.Errorf("leaked %s: %s", name, got)
			}
		}
		fmt.Fprint(w, "{}")
	}))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing origin auth")
		}
		http.Redirect(w, r, foreign.URL, http.StatusFound)
	}))
	defer origin.Close()
	cfg := defaultConfig()
	cfg.URL = origin.URL
	cfg.Bearer = "secret"
	cfg.Headers = headerList{{"X-Api-Key", "secret"}, {"Cookie", "manual=secret"}}
	c := clientFor(t, cfg)
	for _, u := range []string{origin.URL, foreign.URL} {
		if _, _, _, err := c.get(u); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProviderHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Environment-Key") != "provider" {
			t.Error("missing provider header")
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("leaked origin auth")
		}
		fmt.Fprint(w, "{}")
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.URL = "https://origin.example"
	cfg.Bearer = "secret"
	c := clientFor(t, cfg)
	if _, _, err := getWithHeader(c, server.URL, "X-Environment-Key", "provider"); err != nil {
		t.Fatal(err)
	}
	if len(c.headers) != 1 {
		t.Fatal("mutated client")
	}
}

func TestLoginSessionRoundTrip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["otp"] != "123" {
			t.Error("login-extra ignored")
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "secret", Path: "/private", HttpOnly: true})
		fmt.Fprint(w, "{}")
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.LoginURL = server.URL + "/login"
	cfg.LoginJSON = "{}"
	cfg.LoginExtra = kvList{{"otp", "123"}}
	c := clientFor(t, cfg)
	if err := c.doLogin(cfg); err != nil {
		t.Fatal(err)
	}
	// Preserve secure, expiry, host-only, and deletion semantics.
	u, _ := url.Parse(server.URL)
	c.http.Jar.SetCookies(u, []*http.Cookie{{Name: "expired", Value: "old", Path: "/", Expires: time.Now().Add(-time.Hour)}})
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := c.saveSession(path); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("insecure session permissions")
	}
	cfg.Session = path
	cfg.URL = server.URL
	restored := clientFor(t, cfg)
	private, _ := url.Parse(server.URL + "/private")
	cookies := restored.http.Jar.Cookies(private)
	if len(cookies) != 1 || cookies[0].Name != "sid" {
		t.Fatalf("lost cookies: %v", cookies)
	}
	if len(restored.http.Jar.Cookies(u)) != 0 {
		t.Fatal("cookie scope widened")
	}
	cfg.URL = "https://other.example"
	if _, err := newClient(cfg); err == nil {
		t.Fatal("accepted foreign session")
	}
}

func TestScanComparisonAndSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/main.js" {
			fmt.Fprint(w, `window.__FLAGS__={"flags":{"shared":true}}`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "rotated", Value: "new", Path: "/"})
		flag := "publicAccess"
		if r.Header.Get("Authorization") != "" {
			flag = "staffAccess"
		}
		fmt.Fprintf(w, `<script type="application/json">{"flags":{"%s":true}}</script><script src="/main.js"></script>`, flag)
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.URL = server.URL
	cfg.Bearer = "secret"
	cfg.NoProbe = true
	cfg.CompareAnon = true
	cfg.CacheDir = t.TempDir()
	cfg.SaveSession = filepath.Join(t.TempDir(), "session.json")
	rep, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.AuthOnlyFlags, ",") != "staffAccess" || strings.Join(rep.AnonOnlyFlags, ",") != "publicAccess" {
		t.Fatalf("bad diff: %+v", rep)
	}
	for _, entry := range []struct{ path, key string }{{"document.html", "staffAccess"}, {"anon/document.html", "publicAccess"}} {
		body, err := os.ReadFile(filepath.Join(cfg.CacheDir, entry.path))
		if err != nil || !strings.Contains(string(body), entry.key) {
			t.Fatalf("cache %s: %s %v", entry.path, body, err)
		}
	}
	saved, _ := os.ReadFile(cfg.SaveSession)
	if !strings.Contains(string(saved), "rotated") {
		t.Fatal("saved session before scan")
	}
	cfg.SaveSession = filepath.Join(t.TempDir(), "missing", "session.json")
	if _, err := Scan(cfg); err == nil {
		t.Fatal("ignored save error")
	}
}

func TestHarvest(t *testing.T) {
	acc := newHarvest()
	harvest(`const sdk = "statsig"; const url="https://cdn.growthbook.io/api/features/abc123xyz";
 <script type="application/json">{"flags":{"checkout":true,"theme":"dark"}}</script>`, "fixture", acc)
	if _, ok := acc.platforms["statsig"]; !ok {
		t.Error("missed SDK")
	}
	if _, ok := acc.keys["growthbook|abc123xyz"]; !ok {
		t.Error("missed URL key")
	}
	if f := acc.flags["checkout"]; f.Value != "true" || f.On == nil || !*f.On {
		t.Errorf("missed flag: %+v", f)
	}
	if acc.flags["theme"].Value != `"dark"` {
		t.Error("missed variant")
	}
	if got := extractQuotedJS(`import("./chunk-lazy.js")`, "https://example.com/assets/main.js"); len(got) != 1 || got[0] != "https://example.com/assets/chunk-lazy.js" {
		t.Fatalf("missed relative chunk: %v", got)
	}
}

func TestJSLimit(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			hits++
			http.Error(w, "missing", 404)
			return
		}
		fmt.Fprint(w, `<script src="/one.js"></script><script src="/two.js"></script>`)
	}))
	defer server.Close()
	for _, limit := range []int{0, 1} {
		hits = 0
		cfg := defaultConfig()
		cfg.URL = server.URL
		cfg.CacheDir = t.TempDir()
		cfg.NoProbe = true
		cfg.JSLimit = limit
		if _, err := Scan(cfg); err != nil {
			t.Fatal(err)
		}
		if hits != limit {
			t.Fatalf("limit %d made %d requests", limit, hits)
		}
	}
}

func TestCookieFileAndHeaderOverrides(t *testing.T) {
	cfg := defaultConfig()
	cfg.URL = "https://example.com"
	cfg.Cookie = "a=one\nb=two"
	c := clientFor(t, cfg)
	if c.cookieCount() != 2 {
		t.Fatal("newline cookie parsing")
	}
	path := filepath.Join(t.TempDir(), "session.json")
	c.headers = [][2]string{{"Authorization", "Bearer old"}}
	if err := c.saveSession(path); err != nil {
		t.Fatal(err)
	}
	cfg.Session = path
	cfg.Bearer = "new"
	c = clientFor(t, cfg)
	req, _ := http.NewRequest("GET", cfg.URL, nil)
	c.applyHeaders(req)
	if req.Header.Get("Authorization") != "Bearer new" {
		t.Fatal("saved credentials override CLI")
	}
}

func TestProbeErrorsAndPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
	}))
	defer server.Close()
	cfg := defaultConfig()
	cfg.URL = server.URL
	c := clientFor(t, cfg)
	if _, _, err := getSilent(c, server.URL); err == nil {
		t.Error("GET hid HTTP error")
	}
	if _, _, err := c.postJSON(server.URL, map[string]string{}); err == nil {
		t.Error("POST hid HTTP error")
	}
	acc := newHarvest()
	if n := ingestConfigCat([]byte(`{"p":{"u":"cdn"},"f":{"checkout":{"t":0,"v":{"b":true}}}}`), acc); n != 1 {
		t.Fatalf("ConfigCat flags: %d", n)
	}
	if _, ok := acc.flags["checkout"]; !ok {
		t.Error("missing ConfigCat key")
	}
	ingestLD([]byte(`{"theme":{"value":"dark"}}`), acc)
	if acc.flags["theme"].On != nil {
		t.Error("string variant reported off")
	}
}
