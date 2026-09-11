package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"
)

type httpClient struct {
	http    *http.Client
	headers [][2]string
	base    *url.URL
}

type sessionFile struct {
	Cookies []savedCookie  `json:"cookies"`
	Headers [][2]string    `json:"headers"`
	Bearer  string         `json:"bearer,omitempty"`
}

type savedCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
	Secure bool   `json:"secure"`
}

func newClient(cfg *Config) (*httpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure, //nolint:gosec
		},
	}
	c := &httpClient{
		http: &http.Client{
			Jar:     jar,
			Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		headers: append([][2]string{}, cfg.Headers...),
	}
	if cfg.Bearer != "" {
		c.headers = append(c.headers, [2]string{"Authorization", "Bearer " + cfg.Bearer})
	}
	if cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err == nil {
			c.base = u
		}
	}
	if cfg.Session != "" {
		if err := c.loadSession(cfg.Session); err != nil {
			return nil, fmt.Errorf("load session: %w", err)
		}
	}
	if cfg.CookieFile != "" {
		b, err := os.ReadFile(cfg.CookieFile)
		if err != nil {
			return nil, err
		}
		cfg.Cookie = strings.TrimSpace(string(b))
	}
	if cfg.Cookie != "" && c.base != nil {
		c.setCookieHeader(c.base, cfg.Cookie)
	}
	return c, nil
}

func (c *httpClient) setCookieHeader(u *url.URL, raw string) {
	var cookies []*http.Cookie
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:   strings.TrimSpace(name),
			Value:  strings.TrimSpace(val),
			Path:   "/",
			Domain: u.Hostname(),
		})
	}
	c.http.Jar.SetCookies(u, cookies)
}

func (c *httpClient) doLogin(cfg *Config) error {
	var body io.Reader
	ctype := ""
	if cfg.LoginJSON != "" {
		body = strings.NewReader(cfg.LoginJSON)
		ctype = "application/json"
	} else if cfg.LoginUser != "" || cfg.LoginPass != "" {
		form := url.Values{}
		form.Set(cfg.LoginUserField, cfg.LoginUser)
		form.Set(cfg.LoginPassField, cfg.LoginPass)
		for _, kv := range cfg.LoginExtra {
			form.Set(kv[0], kv[1])
		}
		body = strings.NewReader(form.Encode())
		ctype = "application/x-www-form-urlencoded"
	} else if len(cfg.LoginExtra) > 0 {
		form := url.Values{}
		for _, kv := range cfg.LoginExtra {
			form.Set(kv[0], kv[1])
		}
		body = strings.NewReader(form.Encode())
		ctype = "application/x-www-form-urlencoded"
	} else {
		return fmt.Errorf("login-url set but no --login-json / --login-user / --login-extra")
	}
	req, err := http.NewRequest(http.MethodPost, cfg.LoginURL, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("Accept", "application/json, text/html, */*")
	c.applyHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("login HTTP %d: %s", resp.StatusCode, truncate(string(b), 200))
	}
	// Some APIs return a token instead of Set-Cookie.
	var payload map[string]any
	if json.Unmarshal(b, &payload) == nil {
		if tok := firstString(payload, "token", "access_token", "accessToken", "jwt", "id_token"); tok != "" {
			c.headers = append(c.headers, [2]string{"Authorization", "Bearer " + tok})
		}
		if tok := firstString(payload, "session", "sessionId", "session_id"); tok != "" && c.base != nil {
			c.setCookieHeader(c.base, "session="+tok)
		}
	}
	return nil
}

func (c *httpClient) get(rawURL string) (status int, final string, body []byte, err error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ffactory/1.0; +https://kapeka.dev/blog/exploiting-the-feature-factory)")
	c.applyHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	final = rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return resp.StatusCode, final, b, err
}

func (c *httpClient) postJSON(rawURL string, payload any) (status int, body []byte, err error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, rawURL, &buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ffactory/1.0)")
	c.applyHeaders(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, b, err
}

func (c *httpClient) applyHeaders(req *http.Request) {
	for _, h := range c.headers {
		req.Header.Set(h[0], h[1])
	}
}

func (c *httpClient) cookieCount() int {
	if c.base == nil {
		return 0
	}
	return len(c.http.Jar.Cookies(c.base))
}

func (c *httpClient) saveSession(path string) error {
	sf := sessionFile{Headers: c.headers}
	if c.base != nil {
		for _, ck := range c.http.Jar.Cookies(c.base) {
			sf.Cookies = append(sf.Cookies, savedCookie{
				Name:   ck.Name,
				Value:  ck.Value,
				Domain: c.base.Hostname(),
				Path:   "/",
			})
		}
	}
	b, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (c *httpClient) loadSession(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var sf sessionFile
	if err := json.Unmarshal(b, &sf); err != nil {
		return err
	}
	if len(sf.Headers) > 0 {
		c.headers = append(c.headers, sf.Headers...)
	}
	if c.base != nil && len(sf.Cookies) > 0 {
		var cookies []*http.Cookie
		for _, ck := range sf.Cookies {
			cookies = append(cookies, &http.Cookie{
				Name:   ck.Name,
				Value:  ck.Value,
				Path:   ck.Path,
				Domain: ck.Domain,
				Secure: ck.Secure,
			})
		}
		c.http.Jar.SetCookies(c.base, cookies)
	}
	return nil
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	// one level of nesting (data.token)
	if data, ok := m["data"].(map[string]any); ok {
		for _, k := range keys {
			if v, ok := data[k]; ok {
				if s, ok := v.(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
