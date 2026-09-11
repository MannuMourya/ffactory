package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	reTitle        = regexp.MustCompile(`(?is)<title[^>]*>([^<]+)</title>`)
	reScriptSrc    = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	reAbsURL       = regexp.MustCompile(`https?://[a-zA-Z0-9._:~/-]+`)
	reClientKey    = regexp.MustCompile(`(?i)((?:sdk|client|phc|env)[-_][A-Za-z0-9]{8,}|ldClientSideId["'\s:=]+[A-Za-z0-9-]{8,})`)
	reLDID         = regexp.MustCompile(`(?i)(?:client[_-]?side[_-]?id|ldClientSideId)["'\s:=]+["']?([a-z0-9-]{8,})`)
	reGBKey        = regexp.MustCompile(`(?i)(?:sdk-[A-Za-z0-9]{10,}|cdn\.growthbook\.io/api/features/([A-Za-z0-9_-]+))`)
	rePHToken      = regexp.MustCompile(`phc_[A-Za-z0-9]+`)
	reStatsig      = regexp.MustCompile(`client-[a-zA-Z0-9]{20,}`)
	reFlagsmithEnv = regexp.MustCompile(`(?i)(?:X-Environment-Key["'\s:=]+["']([A-Za-z0-9]+)["']|flagsmith["'\s:]+["']([A-Za-z0-9]{16,})["'])`)
	reFlagKey      = regexp.MustCompile(`(?i)(?:FEATURE|FLAG|FF|ENABLE|DISABLE|EXPERIMENT|TOGGLE|RELEASE|BETA|LAUNCH)[_-][A-Z0-9_]{2,}`)
	reCamelFlag    = regexp.MustCompile(`\b(?:is(?:Admin|Staff|Internal|Beta|Pro|Enterprise|Enabled|Disabled)[A-Za-z0-9]*|[A-Za-z][A-Za-z0-9]*(?:Enabled|Disabled|Feature|Flag|Toggle|Experiment))\b`)
	reKVBool       = regexp.MustCompile(`["']([A-Za-z][A-Za-z0-9_-]{2,})["']\s*:\s*(true|false)`)
	reProcessEnv   = regexp.MustCompile(`process\.env\.([A-Z][A-Z0-9_]+)`)
	reViteEnv      = regexp.MustCompile(`(?:import\.meta\.env|NEXT_PUBLIC|VITE|REACT_APP)_([A-Z0-9_]+)`)
	reWindowFlags  = regexp.MustCompile(`(?is)window\.(?:__)?(?:FEATURE_FLAGS|APP_CONFIG|FLAGS|ENV|CONFIG|__NEXT_DATA__)[^=]{0,40}=(\{.*?\})`)
	reNextData     = regexp.MustCompile(`(?is)<script id="__NEXT_DATA__" type="application/json">(.*?)</script>`)
	reJSONScript   = regexp.MustCompile(`(?is)<script[^>]+type=["']application/json["'][^>]*>(.*?)</script>`)
	reTypedScript  = regexp.MustCompile(`(?is)<script[^>]+type=["']([^"']+)["'][^>]*>(.*?)</script>`)
	reModulePre    = regexp.MustCompile(`(?is)<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+\.js[^"']*)["']`)
	reProduct      = regexp.MustCompile(`(?i)(?:product[_-]?name|app[_-]?name)\s*[:=]\s*["']([A-Za-z][A-Za-z0-9 ._-]{2,40})["']`)
	reWindowAssign = regexp.MustCompile(`window\.(?:ShData|__APP_CONFIG__|__FEATURE_FLAGS__|__FLAGS__|__ENV__|appConfig|featureFlags)\s*=\s*`)
)

func extractTitle(html string) string {
	m := reTitle.FindStringSubmatch(html)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractScriptSrcs(html, pageURL string) []string {
	base, _ := url.Parse(pageURL)
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "data:") {
			return
		}
		u := raw
		if base != nil {
			if ref, err := base.Parse(raw); err == nil {
				u = ref.String()
			}
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reModulePre.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reTypedScript.FindAllStringSubmatch(html, -1) {
		typ := strings.ToLower(m[1])
		body := strings.TrimSpace(m[2])
		if strings.Contains(typ, "json") || strings.Contains(typ, "config") || strings.Contains(typ, "superhuman") {
			var cfg map[string]any
			if json.Unmarshal([]byte(body), &cfg) == nil {
				for _, k := range []string{"pageJs", "page_js", "main", "bootstrap", "loader"} {
					if s, ok := cfg[k].(string); ok {
						add(s)
					}
				}
			}
		}
	}
	return out
}

func harvest(text, source string, acc *harvestAcc) {
	acc.addURLs(reAbsURL.FindAllString(text, -1), source)
	for _, m := range reLDID.FindAllStringSubmatch(text, -1) {
		acc.addKey("launchdarkly", m[1], source)
	}
	for _, m := range reGBKey.FindAllStringSubmatch(text, -1) {
		k := m[0]
		if m[1] != "" {
			k = m[1]
		}
		if strings.Contains(strings.ToLower(k), "growthbook") || strings.HasPrefix(k, "sdk-") {
			acc.addKey("growthbook", k, source)
		}
	}
	for _, m := range rePHToken.FindAllString(text, -1) {
		acc.addKey("posthog", m, source)
	}
	for _, m := range reStatsig.FindAllString(text, -1) {
		if strings.HasPrefix(m, "client-") {
			acc.addKey("statsig", m, source)
		}
	}
	for _, m := range reFlagsmithEnv.FindAllStringSubmatch(text, -1) {
		k := m[1]
		if k == "" {
			k = m[2]
		}
		if k != "" {
			acc.addKey("flagsmith", k, source)
		}
	}
	for _, m := range reFlagKey.FindAllString(text, -1) {
		acc.addFlag(m, "", source)
	}
	for _, m := range reProcessEnv.FindAllStringSubmatch(text, -1) {
		name := m[1]
		if looksLikeFlag(name) {
			acc.addFlag(name, "", source+":process.env")
		}
	}
	for _, m := range reKVBool.FindAllStringSubmatch(text, -1) {
		key, val := m[1], m[2]
		if looksLikeFlag(key) || interestingBoolKey(key) {
			on := val == "true"
			acc.addFlagVal(key, val, source, &on)
		}
	}
	for _, m := range reProduct.FindAllStringSubmatch(text, -1) {
		name := strings.TrimSpace(m[1])
		if !noisyProduct(name) {
			acc.products[name] = struct{}{}
		}
	}
	for _, blob := range collectJSONBlobs(text) {
		walkJSONFlags(blob, source+":json", acc)
	}
	for _, blob := range extractWindowObjects(text) {
		walkJSONFlags(blob, source+":window", acc)
	}
}

func collectJSONBlobs(text string) []any {
	var blobs []any
	for _, re := range []*regexp.Regexp{reNextData, reJSONScript} {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			var v any
			if json.Unmarshal([]byte(m[1]), &v) == nil {
				blobs = append(blobs, v)
			}
		}
	}
	for _, m := range reTypedScript.FindAllStringSubmatch(text, -1) {
		typ := strings.ToLower(m[1])
		if !(strings.Contains(typ, "json") || strings.Contains(typ, "config") || strings.Contains(typ, "superhuman")) {
			continue
		}
		var v any
		if json.Unmarshal([]byte(m[2]), &v) == nil {
			blobs = append(blobs, v)
		}
	}
	return blobs
}

func extractWindowObjects(text string) []any {
	var blobs []any
	for _, loc := range reWindowAssign.FindAllStringIndex(text, -1) {
		i := loc[1]
		for i < len(text) && text[i] != '{' {
			i++
		}
		if i >= len(text) {
			continue
		}
		raw, ok := sliceBalanced(text, i)
		if !ok {
			continue
		}
		var v any
		if json.Unmarshal([]byte(raw), &v) == nil {
			blobs = append(blobs, v)
		}
	}
	return blobs
}

func sliceBalanced(s string, start int) (string, bool) {
	if start >= len(s) || s[start] != '{' {
		return "", false
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			if esc {
				esc = false
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], true
			}
		}
	}
	return "", false
}

func walkJSONFlags(v any, source string, acc *harvestAcc) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			lk := strings.ToLower(k)
			if lk == "treatments" || lk == "experiments" || lk == "gates" {
				ingestTreatments(val, source+":"+k, acc)
			}
			if lk == "features" || lk == "featureflags" || lk == "flags" || lk == "toggles" ||
				lk == "feature_flags" || lk == "editorfeatures" {
				walkJSONFlags(val, source+":"+k, acc)
			}
			switch cv := val.(type) {
			case bool:
				if looksLikeFlag(k) || interestingBoolKey(k) {
					on := cv
					acc.addFlagVal(k, boolStr(cv), source, &on)
				}
			case string:
				if looksLikeFlag(k) {
					acc.addFlag(k, cv, source)
				}
			case map[string]any, []any:
				if looksLikeFlag(k) || interestingBoolKey(k) {
					acc.addFlag(k, stringify(val), source)
				}
				walkJSONFlags(val, source, acc)
			}
		}
	case []any:
		for _, item := range t {
			walkJSONFlags(item, source, acc)
		}
	}
}

func ingestTreatments(v any, source string, acc *harvestAcc) {
	arr, ok := v.([]any)
	if !ok {
		walkJSONFlags(v, source, acc)
		return
	}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := strField(m, "experimentName", "name", "gateName", "key", "flag")
		if name == "" {
			continue
		}
		val := strField(m, "groupName", "value", "variation", "status")
		src := strings.ToLower(strField(m, "source", "provider"))
		typ := strField(m, "type")
		if typ != "" && val != "" {
			val = typ + ":" + val
		}
		note := source
		if src != "" {
			note = source + ":" + src
			if src == "statsig" || src == "launchdarkly" || src == "growthbook" || src == "optimizely" || src == "posthog" || src == "unleash" || src == "flagsmith" {
				acc.platforms[src] = struct{}{}
			}
		}
		acc.addFlag(name, val, note)
	}
}

func strField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func looksLikeFlag(k string) bool {
	u := strings.ToUpper(k)
	for _, p := range []string{"FEATURE", "FLAG", "FF_", "ENABLE", "DISABLE", "EXPERIMENT", "TOGGLE", "RELEASE", "BETA", "LAUNCH", "UNLEASH"} {
		if strings.Contains(u, p) {
			return true
		}
	}
	l := strings.ToLower(k)
	return strings.HasSuffix(l, "enabled") || strings.HasSuffix(l, "disabled") ||
		strings.HasSuffix(l, "feature") || strings.HasSuffix(l, "flag")
}

func interestingBoolKey(k string) bool {
	l := strings.ToLower(k)
	needles := []string{
		"admin", "staff", "internal", "beta", "preview", "canary", "gate",
		"pro", "enterprise", "premium", "paid", "godmode", "god_mode",
		"wallet", "agent", "import", "github", "slack", "enabled",
		"disabled", "allow", "deny", "access",
	}
	for _, n := range needles {
		if strings.Contains(l, n) {
			return true
		}
	}
	return false
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func stringify(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > 180 {
		return s[:180] + "…"
	}
	return s
}

type harvestAcc struct {
	keys      map[string]ClientKey
	evals     map[string]EvalURL
	flags     map[string]Flag
	hosts     map[string]struct{}
	products  map[string]struct{}
	platforms map[string]struct{}
}

func newHarvest() *harvestAcc {
	return &harvestAcc{
		keys:      map[string]ClientKey{},
		evals:     map[string]EvalURL{},
		flags:     map[string]Flag{},
		hosts:     map[string]struct{}{},
		products:  map[string]struct{}{},
		platforms: map[string]struct{}{},
	}
}

func (h *harvestAcc) addKey(platform, key, source string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	id := platform + "|" + key
	if _, ok := h.keys[id]; ok {
		return
	}
	h.keys[id] = ClientKey{Platform: platform, Key: key, Source: source}
	h.platforms[platform] = struct{}{}
}

func (h *harvestAcc) addEval(platform, raw, source string) {
	raw = strings.TrimRight(raw, ".,);'\"")
	if raw == "" {
		return
	}
	if _, ok := h.evals[raw]; ok {
		return
	}
	h.evals[raw] = EvalURL{Platform: platform, URL: raw, Source: source}
	h.platforms[platform] = struct{}{}
}

func (h *harvestAcc) addFlag(key, val, source string) {
	h.addFlagVal(key, val, source, nil)
}

func (h *harvestAcc) addFlagVal(key, val, source string, on *bool) {
	key = strings.TrimSpace(key)
	if len(key) < 3 || len(key) > 80 {
		return
	}
	if noisyFlag(key) {
		return
	}
	if existing, ok := h.flags[key]; ok {
		if existing.Value == "" && val != "" {
			existing.Value = val
			existing.On = on
			h.flags[key] = existing
		}
		return
	}
	h.flags[key] = Flag{Key: key, Value: val, Source: source, On: on}
}

func (h *harvestAcc) addURLs(urls []string, source string) {
	for _, raw := range urls {
		raw = strings.TrimRight(raw, ".,);'\"")
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Host)
		plat, kind := classifyHost(host, u.Path)
		if plat != "" {
			h.platforms[plat] = struct{}{}
			if kind == "eval" || kind == "cdn" {
				h.addEval(plat, raw, source)
			}
		}
		if isFactoryHost(host) {
			h.hosts[host] = struct{}{}
		}
	}
}

func (h *harvestAcc) sortedFlags() []Flag {
	out := make([]Flag, 0, len(h.flags))
	for _, f := range h.flags {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (h *harvestAcc) sortedKeys() []ClientKey {
	out := make([]ClientKey, 0, len(h.keys))
	for _, k := range h.keys {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Platform+out[i].Key < out[j].Platform+out[j].Key })
	return out
}

func (h *harvestAcc) sortedEvals() []EvalURL {
	out := make([]EvalURL, 0, len(h.evals))
	for _, e := range h.evals {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func (h *harvestAcc) sortedPlatforms() []string {
	return sortedKeys(h.platforms)
}

func (h *harvestAcc) sortedHosts(exclude string) []string {
	ex := strings.ToLower(exclude)
	var out []string
	for hst := range h.hosts {
		if hst == ex || strings.HasSuffix(ex, hst) {
			continue
		}
		out = append(out, hst)
	}
	sort.Strings(out)
	return out
}

func (h *harvestAcc) sortedProducts() []string {
	return sortedKeys(h.products)
}

func noisyFlag(k string) bool {
	l := strings.ToLower(k)
	exact := map[string]struct{}{
		"disabled": {}, "enabled": {}, "disable": {}, "enable": {},
		"flag": {}, "flags": {}, "feature": {}, "features": {},
		"toggle": {}, "experimentid": {}, "experimentname": {},
		"flag-icon": {}, "flag-fill": {}, "toggle-left": {}, "toggle-right": {},
		"toggle-icon": {}, "toggle-open": {}, "toggle-active": {}, "toggle-content": {},
		"disable-selection": {}, "disable-styles": {}, "enable-background": {},
		"enable-api": {}, "enable_cookie": {}, "disable-when": {},
		"flag_include_prerelease": {}, "flag_loose": {}, "release_types": {},
		"feature_unspecified": {}, "feature_not_implemented": {},
		"isexperimentalcompile": {}, "pageprops": {}, "props": {},
	}
	if _, ok := exact[l]; ok {
		return true
	}
	if strings.Contains(l, "toggle_") && strings.ContainsAny(l, "0123456789") {
		return true
	}
	if strings.HasPrefix(l, "feature__") {
		return true
	}
	if strings.HasPrefix(l, "ff-") && len(l) < 10 {
		return true
	}
	// ISO country-flag icon classes (flag-us, flag-cz)
	if strings.HasPrefix(l, "flag-") && len(l) <= 8 {
		return true
	}
	return false
}

func noisyProduct(n string) bool {
	l := strings.ToLower(n)
	if strings.Contains(l, "color") || strings.Contains(l, "logo") || strings.Contains(l, "icon") {
		return true
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
