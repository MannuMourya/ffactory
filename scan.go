package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func Scan(cfg *Config) (*Report, error) {
	if cfg.JSLimit < 0 {
		return nil, fmt.Errorf("js-limit must not be negative")
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
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
	authRep, err := scanOnce(c, cfg, false)
	if err != nil {
		return nil, err
	}

	if cfg.SaveSession != "" {
		if err := c.saveSession(cfg.SaveSession); err != nil {
			return nil, fmt.Errorf("save session: %w", err)
		}
	}
	// Compare document/bundle discoveries before adding authenticated API results.
	documentFlags := append([]Flag(nil), authRep.Flags...)
	if !cfg.NoProbe {
		acc := newHarvest()
		for _, f := range authRep.Flags {
			acc.flags[f.Key] = f
		}
		for _, k := range authRep.ClientKeys {
			acc.addKey(k.Platform, k.Key, k.Source)
		}
		for _, e := range authRep.EvalURLs {
			acc.addEval(e.Platform, e.URL, e.Source)
		}
		authRep.ProbeResults = probePlatforms(c, cfg, acc)
		authRep.Flags = acc.sortedFlags()
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
		anonCfg.CacheDir = filepath.Join(cfg.CacheDir, "anon")
		if err := os.MkdirAll(anonCfg.CacheDir, 0o700); err != nil {
			return nil, err
		}
		anonClient, err := newClient(&anonCfg)
		if err != nil {
			return nil, err
		}
		anonRep, err := scanOnce(anonClient, &anonCfg, false)
		if err != nil {
			authRep.Notes = append(authRep.Notes, "anonymous comparison failed: "+err.Error())
		} else if anonRep.DocumentStatus >= 400 {
			authRep.Notes = append(authRep.Notes, fmt.Sprintf("anonymous comparison failed: HTTP %d", anonRep.DocumentStatus))
		} else {
			authRep.AuthOnlyFlags, authRep.AnonOnlyFlags = diffFlags(documentFlags, anonRep.Flags)
			authRep.ValueChanges = diffValues(documentFlags, anonRep.Flags)
			authRep.Notes = append(authRep.Notes, fmt.Sprintf("anon compare: %d auth-only, %d anon-only", len(authRep.AuthOnlyFlags), len(authRep.AnonOnlyFlags)))
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
	if err := writePrivate(filepath.Join(cfg.CacheDir, "document.html"), body); err != nil {
		return nil, err
	}

	acc := newHarvest()
	harvest(html, "document", acc)

	pageURL := final
	if pageURL == "" {
		pageURL = cfg.URL
	}
	scripts := extractScriptSrcs(html, pageURL)
	endpoints := extractEndpoints(html, "document", pageURL)
	assets := []Asset{{Source: "document", URL: cfg.URL, FinalURL: final, Status: status}}
	baseHost := ""
	if u, err := url.Parse(pageURL); err == nil {
		baseHost = strings.ToLower(u.Hostname())
	}

	var fetched []string
	limit := cfg.JSLimit

	n := 0
	attempts := 0
	queue := append([]string{}, scripts...)
	seenJS := map[string]struct{}{}
	for len(queue) > 0 && attempts < limit {
		src := queue[0]
		queue = queue[1:]
		if _, ok := seenJS[src]; ok {
			continue
		}
		seenJS[src] = struct{}{}
		if !firstParty(src, baseHost) && n > 8 && !maybeFlagSDK(src) {
			continue
		}
		attempts++
		st, finalJS, js, err := c.get(src)
		if err != nil || st >= 400 || len(js) == 0 {
			continue
		}
		name := fmt.Sprintf("js-%02d.js", n)
		if err := writePrivate(filepath.Join(cfg.CacheDir, name), js); err != nil {
			return nil, err
		}
		txt := string(js)
		harvest(txt, name, acc)
		endpoints = append(endpoints, extractEndpoints(txt, name, pageURL)...)
		assets = append(assets, Asset{Source: name, URL: src, FinalURL: finalJS, Status: st})
		fetched = append(fetched, src)
		n++
		// loaders often point at the real bundle (pageJs, import(), webpack)
		for _, extra := range extractScriptSrcs(txt, finalJS) {
			if _, ok := seenJS[extra]; !ok {
				queue = append(queue, extra)
			}
		}
		for _, extra := range extractQuotedJS(txt, finalJS) {
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
		Endpoints:      endpoints,
		Assets:         assets,
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
		if !strings.HasPrefix(raw, "~") {
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
	sort.Strings(authOnly)
	sort.Strings(anonOnly)
	return authOnly, anonOnly
}
