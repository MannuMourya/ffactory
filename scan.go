package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func Scan(cfg *Config) (*Report, error) {
	if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
		return nil, err
	}
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.LoginURL != "" {
		if err := c.doLogin(cfg); err != nil {
			return nil, fmt.Errorf("login: %w", err)
		}
	}
	if cfg.SaveSession != "" {
		_ = c.saveSession(cfg.SaveSession)
	}

	authRep, err := scanOnce(c, cfg, true)
	if err != nil {
		return nil, err
	}

	authed := cfg.Cookie != "" || cfg.CookieFile != "" || cfg.Bearer != "" ||
		cfg.Session != "" || cfg.LoginURL != "" || len(cfg.Headers) > 0
	authRep.Authenticated = authed

	if cfg.CompareAnon && authed {
		anonCfg := *cfg
		anonCfg.Cookie = ""
		anonCfg.CookieFile = ""
		anonCfg.Bearer = ""
		anonCfg.Session = ""
		anonCfg.LoginURL = ""
		anonCfg.Headers = nil
		anonCfg.SaveSession = ""
		anonClient, err := newClient(&anonCfg)
		if err == nil {
			if anonRep, err := scanOnce(anonClient, &anonCfg, false); err == nil {
				authRep.AuthOnlyFlags, authRep.AnonOnlyFlags = diffFlags(authRep.Flags, anonRep.Flags)
				authRep.Notes = append(authRep.Notes, fmt.Sprintf("anon compare: %d auth-only, %d anon-only", len(authRep.AuthOnlyFlags), len(authRep.AnonOnlyFlags)))
			}
		}
	}
	return authRep, nil
}

func scanOnce(c *httpClient, cfg *Config, doProbe bool) (*Report, error) {
	status, final, body, err := c.get(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch document: %w", err)
	}
	html := string(body)
	_ = os.WriteFile(filepath.Join(cfg.CacheDir, "document.html"), body, 0o644)

	acc := newHarvest()
	harvest(html, "document", acc)

	pageURL := final
	if pageURL == "" {
		pageURL = cfg.URL
	}
	scripts := extractScriptSrcs(html, pageURL)
	baseHost := ""
	if u, err := url.Parse(pageURL); err == nil {
		baseHost = strings.ToLower(u.Hostname())
	}

	var fetched []string
	limit := cfg.JSLimit
	if limit <= 0 {
		limit = 30
	}
	n := 0
	queue := append([]string{}, scripts...)
	seenJS := map[string]struct{}{}
	for len(queue) > 0 && n < limit {
		src := queue[0]
		queue = queue[1:]
		if _, ok := seenJS[src]; ok {
			continue
		}
		seenJS[src] = struct{}{}
		if !firstParty(src, baseHost) && n > 8 && !maybeFlagSDK(src) {
			continue
		}
		st, _, js, err := c.get(src)
		if err != nil || st >= 400 || len(js) == 0 {
			continue
		}
		name := fmt.Sprintf("js-%02d.js", n)
		_ = os.WriteFile(filepath.Join(cfg.CacheDir, name), js, 0o644)
		txt := string(js)
		harvest(txt, name, acc)
		fetched = append(fetched, src)
		n++
		// loaders often point at the real bundle (pageJs, import(), webpack)
		for _, extra := range extractScriptSrcs(txt, src) {
			if _, ok := seenJS[extra]; !ok {
				queue = append(queue, extra)
			}
		}
		for _, extra := range extractQuotedJS(txt, src) {
			if _, ok := seenJS[extra]; !ok {
				queue = append(queue, extra)
			}
		}
	}

	var probes []Probe
	if doProbe && !cfg.NoProbe {
		probes = probePlatforms(c, cfg, acc)
	}

	host := baseHost
	rep := &Report{
		Target:         cfg.URL,
		DocumentStatus: status,
		Title:          extractTitle(html),
		FinalURL:       final,
		Platforms:      acc.sortedPlatforms(),
		ClientKeys:     acc.sortedKeys(),
		EvalURLs:       acc.sortedEvals(),
		Flags:          acc.sortedFlags(),
		SecondaryHosts: acc.sortedHosts(host),
		ProductNames:   acc.sortedProducts(),
		JSBundles:      fetched,
		ProbeResults:   probes,
		ScannedAt:      time.Now().UTC(),
	}
	if status >= 400 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("document HTTP %d — session may be stale", status))
	}
	if !cfg.NoProbe && len(acc.keys) == 0 && len(acc.evals) == 0 {
		rep.Notes = append(rep.Notes, "no SaaS client keys found; hunt homegrown flags in document.html + cached JS")
	}
	if cfg.UserID == "" && len(acc.keys) > 0 {
		rep.Notes = append(rep.Notes, "pass --user-id so eval APIs return targeted (staff/plan) flags")
	}
	return rep, nil
}

func firstParty(src, baseHost string) bool {
	u, err := url.Parse(src)
	if err != nil || u.Host == "" {
		return true
	}
	h := strings.ToLower(u.Hostname())
	if baseHost == "" {
		return true
	}
	return h == baseHost || strings.HasSuffix(h, "."+baseHost) || strings.HasSuffix(baseHost, "."+h)
}

func extractQuotedJS(text, pageURL string) []string {
	base, _ := url.Parse(pageURL)
	re := regexp.MustCompile(`["']([^"']+?(?:page|main|app|bundle|chunk)[^"']*?\.js)["']`)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		raw := m[1]
		if strings.HasPrefix(raw, "http") || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "~") {
			u := raw
			if base != nil {
				if ref, err := base.Parse(raw); err == nil {
					u = ref.String()
				}
			}
			if _, ok := seen[u]; ok {
				continue
			}
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func maybeFlagSDK(src string) bool {
	l := strings.ToLower(src)
	for _, n := range []string{
		"launchdarkly", "growthbook", "unleash", "flagsmith", "statsig",
		"optimizely", "split.io", "configcat", "posthog", "ldclient",
	} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func diffFlags(auth, anon []Flag) (authOnly, anonOnly []string) {
	am := map[string]string{}
	nm := map[string]string{}
	for _, f := range auth {
		am[f.Key] = f.Value
	}
	for _, f := range anon {
		nm[f.Key] = f.Value
	}
	for k := range am {
		if _, ok := nm[k]; !ok {
			authOnly = append(authOnly, k)
		}
	}
	for k := range nm {
		if _, ok := am[k]; !ok {
			anonOnly = append(anonOnly, k)
		}
	}
	return authOnly, anonOnly
}
