package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func classifyHost(host, path string) (platform, kind string) {
	h := strings.ToLower(host)
	p := strings.ToLower(path)
	switch {
	case strings.Contains(h, "launchdarkly.com") || strings.Contains(h, "ldusr.com"):
		kind = "cdn"
		if strings.Contains(p, "eval") || strings.Contains(h, "clientstream") || strings.Contains(p, "/sdk/") {
			kind = "eval"
		}
		return "launchdarkly", kind
	case strings.Contains(h, "growthbook.io") || strings.Contains(h, "growthbook.com"):
		kind = "cdn"
		if strings.Contains(p, "/api/features") || strings.Contains(p, "/api/eval") {
			kind = "eval"
		}
		return "growthbook", kind
	case strings.Contains(h, "unleash") || strings.Contains(h, "getunleash.io"):
		kind = "cdn"
		if strings.Contains(p, "/api/frontend") || strings.Contains(p, "/api/client/features") {
			kind = "eval"
		}
		return "unleash", kind
	case strings.Contains(h, "flagsmith.com"):
		kind = "eval"
		return "flagsmith", kind
	case strings.Contains(h, "statsig.com") || strings.Contains(h, "statsigapi.net") || strings.Contains(h, "featuregates.org"):
		kind = "eval"
		return "statsig", kind
	case strings.Contains(h, "optimizely.com"):
		kind = "cdn"
		if strings.Contains(p, "datafile") {
			kind = "eval"
		}
		return "optimizely", kind
	case strings.Contains(h, "split.io"):
		return "split", "cdn"
	case strings.Contains(h, "cdn.configcat.com") || strings.Contains(p, "configuration-files"):
		kind = "cdn"
		if strings.Contains(p, "configuration-files") {
			kind = "eval"
		}
		return "configcat", kind
	case strings.Contains(h, "posthog.com") || strings.Contains(p, "/decide"):
		if strings.Contains(p, "/decide") {
			return "posthog", "eval"
		}
		if strings.Contains(h, "posthog") {
			return "posthog", "cdn"
		}
	}
	return "", ""
}

func isFactoryHost(host string) bool {
	h := strings.ToLower(host)
	// skip static CDNs and the flag SaaS themselves
	skip := []string{
		"googleapis.com", "gstatic.com", "google.com", "facebook.com", "fbcdn.net",
		"twitter.com", "x.com", "cloudflare.com", "cloudfront.net", "akamai",
		"jquery.com", "jsdelivr.net", "unpkg.com", "cdnjs.", "sentry.io",
		"stripe.com", "paypal.com", "github.com", "githubusercontent.com",
		"launchdarkly.com", "growthbook.io", "flagsmith.com", "statsig.com",
		"optimizely.com", "split.io", "configcat.com", "posthog.com",
		"intercom.io", "segment.com", "amplitude.com", "hotjar.com",
		"w3.org", "schema.org", "jqueryui.com", "parsely.com",
		"transcend.io", "transcend-cdn.com", "chinacloudapi.cn",
		"fullstory.com", "cookielaw.org", "onetrust.com",
		"newrelic.com", "nr-data.net", "datadoghq.com",
	}
	for _, s := range skip {
		if strings.Contains(h, s) {
			return false
		}
	}
	needles := []string{
		"app.", "apps.", "labs.", "lab.", "beta.", "staging.", "stage.",
		"preview.", "canary.", "edge.", "agents.", "agent.", "wallet.",
		"studio.", "console.", "admin.", "internal.", "dash.", "dashboard.",
		"api.", "gateway.", "platform.",
	}
	for _, n := range needles {
		if strings.Contains(h, n) {
			return true
		}
	}
	return false
}

func detectPlatformsInText(text string, acc *harvestAcc) {
	l := strings.ToLower(text)
	mapping := map[string]string{
		"launchdarkly": "launchdarkly",
		"ldclient":     "launchdarkly",
		"growthbook":   "growthbook",
		"unleash":      "unleash",
		"flagsmith":    "flagsmith",
		"statsig":      "statsig",
		"optimizely":   "optimizely",
		"split.io":     "split",
		"configcat":    "configcat",
		"posthog":      "posthog",
	}
	for needle, plat := range mapping {
		if strings.Contains(l, needle) {
			acc.platforms[plat] = struct{}{}
		}
	}
}

func probePlatforms(c *httpClient, cfg *Config, acc *harvestAcc) []Probe {
	var probes []Probe
	attrs := map[string]any{}
	if cfg.UserID != "" {
		attrs["id"] = cfg.UserID
		attrs["userId"] = cfg.UserID
		attrs["userID"] = cfg.UserID
		attrs["distinct_id"] = cfg.UserID
		attrs["key"] = cfg.UserID
		attrs["identifier"] = cfg.UserID
	}
	for _, kv := range cfg.Attrs {
		attrs[kv[0]] = kv[1]
	}

	// GrowthBook features + remote eval
	for _, ck := range acc.keys {
		if ck.Platform != "growthbook" {
			continue
		}
		key := ck.Key
		if strings.Contains(key, "/") {
			continue
		}
		u := "https://cdn.growthbook.io/api/features/" + key
		st, body, err := getSilent(c, u)
		p := Probe{Platform: "growthbook", URL: u, Status: st}
		if err != nil {
			p.Note = err.Error()
		} else {
			n := ingestGrowthBook(body, acc)
			p.FlagCount = n
			p.Note = fmt.Sprintf("features dumped (%d)", n)
		}
		probes = append(probes, p)
		if cfg.UserID != "" {
			eu := "https://api.growthbook.io/api/eval/" + key
			st, body, err = c.postJSON(eu, attrs)
			p = Probe{Platform: "growthbook", URL: eu, Status: st}
			if err != nil {
				p.Note = err.Error()
			} else {
				n := ingestGrowthBook(body, acc)
				p.FlagCount = n
				p.Note = "remote eval with user-id"
			}
			probes = append(probes, p)
		}
	}

	// LaunchDarkly evalx
	for _, ck := range acc.keys {
		if ck.Platform != "launchdarkly" {
			continue
		}
		ctx := map[string]any{"kind": "user", "key": "anon"}
		if cfg.UserID != "" {
			ctx["key"] = cfg.UserID
		}
		for k, v := range attrs {
			ctx[k] = v
		}
		raw, _ := json.Marshal(ctx)
		enc := base64.RawURLEncoding.EncodeToString(raw)
		u := fmt.Sprintf("https://app.launchdarkly.com/sdk/evalx/%s/contexts/%s", ck.Key, enc)
		st, body, err := getSilent(c, u)
		p := Probe{Platform: "launchdarkly", URL: u, Status: st}
		if err != nil {
			p.Note = err.Error()
		} else {
			n := ingestLD(body, acc)
			p.FlagCount = n
			p.Note = fmt.Sprintf("evalx (%d flags)", n)
		}
		probes = append(probes, p)
	}

	// Flagsmith identities
	for _, ck := range acc.keys {
		if ck.Platform != "flagsmith" {
			continue
		}
		ident := cfg.UserID
		if ident == "" {
			ident = "ffactory-anon"
		}
		u := "https://edge.api.flagsmith.com/api/v1/identities/?identifier=" + url.QueryEscape(ident)
		st, body, hdrErr := getWithHeader(c, u, "X-Environment-Key", ck.Key)
		p := Probe{Platform: "flagsmith", URL: u, Status: st}
		if hdrErr != nil {
			p.Note = hdrErr.Error()
		} else {
			n := ingestFlagsmith(body, acc)
			p.FlagCount = n
			p.Note = fmt.Sprintf("identities (%d)", n)
		}
		probes = append(probes, p)
	}

	// Statsig initialize
	for _, ck := range acc.keys {
		if ck.Platform != "statsig" {
			continue
		}
		payload := map[string]any{
			"user":             map[string]any{"userID": cfg.UserID},
			"statsigMetadata":  map[string]any{"sdkType": "js-client", "sdkVersion": "5.0.0"},
		}
		st, body, err := postWithHeader(c, "https://api.statsig.com/v1/initialize", payload, "STATSIG-API-KEY", ck.Key)
		p := Probe{Platform: "statsig", URL: "https://api.statsig.com/v1/initialize", Status: st}
		if err != nil {
			p.Note = err.Error()
		} else {
			n := ingestStatsig(body, acc)
			p.FlagCount = n
			p.Note = fmt.Sprintf("initialize (%d)", n)
		}
		probes = append(probes, p)
	}

	// PostHog decide
	for _, ck := range acc.keys {
		if ck.Platform != "posthog" {
			continue
		}
		distinct := cfg.UserID
		if distinct == "" {
			distinct = "ffactory-anon"
		}
		payload := map[string]any{"token": ck.Key, "distinct_id": distinct}
		// try common hosted + first-party later via eval urls
		for _, base := range posthogBases(acc) {
			u := strings.TrimRight(base, "/") + "/decide/?v=3"
			st, body, err := c.postJSON(u, payload)
			p := Probe{Platform: "posthog", URL: u, Status: st}
			if err != nil {
				p.Note = err.Error()
			} else {
				n := ingestPostHog(body, acc)
				p.FlagCount = n
				p.Note = fmt.Sprintf("decide (%d)", n)
			}
			probes = append(probes, p)
		}
	}

	// Generic eval URLs already found
	for _, ev := range acc.sortedEvals() {
		if ev.Platform == "growthbook" && strings.Contains(ev.URL, "/api/features/") {
			st, body, err := getSilent(c, ev.URL)
			p := Probe{Platform: ev.Platform, URL: ev.URL, Status: st}
			if err != nil {
				p.Note = err.Error()
			} else {
				p.FlagCount = ingestGrowthBook(body, acc)
			}
			probes = append(probes, p)
		}
		if ev.Platform == "configcat" {
			st, body, err := getSilent(c, ev.URL)
			p := Probe{Platform: ev.Platform, URL: ev.URL, Status: st}
			if err != nil {
				p.Note = err.Error()
			} else {
				p.FlagCount = ingestGenericMap(body, acc, "configcat")
			}
			probes = append(probes, p)
		}
		if ev.Platform == "optimizely" && strings.Contains(ev.URL, "datafile") {
			st, body, err := getSilent(c, ev.URL)
			p := Probe{Platform: ev.Platform, URL: ev.URL, Status: st}
			if err != nil {
				p.Note = err.Error()
			} else {
				p.FlagCount = ingestOptimizely(body, acc)
			}
			probes = append(probes, p)
		}
	}
	return probes
}

func posthogBases(acc *harvestAcc) []string {
	seen := map[string]struct{}{"https://us.i.posthog.com": {}, "https://app.posthog.com": {}}
	for _, ev := range acc.evals {
		if ev.Platform != "posthog" {
			continue
		}
		u, err := url.Parse(ev.URL)
		if err != nil {
			continue
		}
		seen[u.Scheme+"://"+u.Host] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	return out
}

func getSilent(c *httpClient, raw string) (int, []byte, error) {
	st, _, body, err := c.get(raw)
	return st, body, err
}

func getWithHeader(c *httpClient, raw, name, val string) (int, []byte, error) {
	c.headers = append(c.headers, [2]string{name, val})
	defer func() {
		if n := len(c.headers); n > 0 {
			c.headers = c.headers[:n-1]
		}
	}()
	st, _, body, err := c.get(raw)
	return st, body, err
}

func postWithHeader(c *httpClient, raw string, payload any, name, val string) (int, []byte, error) {
	c.headers = append(c.headers, [2]string{name, val})
	defer func() {
		if n := len(c.headers); n > 0 {
			c.headers = c.headers[:n-1]
		}
	}()
	return c.postJSON(raw, payload)
}

func ingestGrowthBook(body []byte, acc *harvestAcc) int {
	var wrap struct {
		Features map[string]any `json:"features"`
	}
	if json.Unmarshal(body, &wrap) != nil || wrap.Features == nil {
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			return 0
		}
		if f, ok := raw["features"].(map[string]any); ok {
			wrap.Features = f
		} else {
			return 0
		}
	}
	n := 0
	for k, v := range wrap.Features {
		acc.addFlag(k, stringify(v), "growthbook-api")
		n++
	}
	return n
}

func ingestLD(body []byte, acc *harvestAcc) int {
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return 0
	}
	n := 0
	for k, v := range raw {
		val := stringify(v)
		on := false
		if m, ok := v.(map[string]any); ok {
			if b, ok := m["value"].(bool); ok {
				on = b
				val = boolStr(b)
			}
		}
		acc.addFlagVal(k, val, "launchdarkly-evalx", &on)
		n++
	}
	return n
}

func ingestFlagsmith(body []byte, acc *harvestAcc) int {
	var wrap struct {
		Flags []struct {
			Feature struct {
				Name string `json:"name"`
			} `json:"feature"`
			Enabled bool `json:"enabled"`
		} `json:"flags"`
	}
	if json.Unmarshal(body, &wrap) != nil {
		return 0
	}
	for _, f := range wrap.Flags {
		on := f.Enabled
		acc.addFlagVal(f.Feature.Name, boolStr(f.Enabled), "flagsmith-identities", &on)
	}
	return len(wrap.Flags)
}

func ingestStatsig(body []byte, acc *harvestAcc) int {
	var wrap struct {
		FeatureGates map[string]any `json:"feature_gates"`
		DynamicCfgs  map[string]any `json:"dynamic_configs"`
	}
	if json.Unmarshal(body, &wrap) != nil {
		return 0
	}
	n := 0
	for k, v := range wrap.FeatureGates {
		acc.addFlag(k, stringify(v), "statsig-initialize")
		n++
	}
	for k, v := range wrap.DynamicCfgs {
		acc.addFlag(k, stringify(v), "statsig-config")
		n++
	}
	return n
}

func ingestPostHog(body []byte, acc *harvestAcc) int {
	var wrap struct {
		Flags map[string]any `json:"featureFlags"`
	}
	if json.Unmarshal(body, &wrap) != nil || wrap.Flags == nil {
		var raw map[string]any
		if json.Unmarshal(body, &raw) != nil {
			return 0
		}
		if f, ok := raw["featureFlags"].(map[string]any); ok {
			wrap.Flags = f
		} else {
			return 0
		}
	}
	n := 0
	for k, v := range wrap.Flags {
		acc.addFlag(k, stringify(v), "posthog-decide")
		n++
	}
	return n
}

func ingestOptimizely(body []byte, acc *harvestAcc) int {
	var wrap struct {
		Features    []struct{ Key string `json:"key"` }    `json:"features"`
		Experiments []struct{ Key string `json:"key"` }    `json:"experiments"`
		FeatureFlags []struct{ Key string `json:"key"` }   `json:"featureFlags"`
	}
	if json.Unmarshal(body, &wrap) != nil {
		return 0
	}
	n := 0
	for _, f := range wrap.Features {
		acc.addFlag(f.Key, "", "optimizely-datafile")
		n++
	}
	for _, f := range wrap.FeatureFlags {
		acc.addFlag(f.Key, "", "optimizely-datafile")
		n++
	}
	for _, f := range wrap.Experiments {
		acc.addFlag(f.Key, "", "optimizely-experiment")
		n++
	}
	return n
}

func ingestGenericMap(body []byte, acc *harvestAcc, source string) int {
	var raw map[string]any
	if json.Unmarshal(body, &raw) != nil {
		return 0
	}
	n := 0
	for k, v := range raw {
		acc.addFlag(k, stringify(v), source)
		n++
	}
	return n
}
