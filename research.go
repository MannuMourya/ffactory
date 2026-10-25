package main

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Evidence describes a static observation, never proof of authorization bypass.
type Evidence struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Value  string `json:"value,omitempty"`
}
type ValueChange struct {
	Key          string     `json:"key"`
	AuthValue    string     `json:"auth_value"`
	AnonValue    string     `json:"anon_value"`
	AuthEvidence []Evidence `json:"auth_evidence"`
	AnonEvidence []Evidence `json:"anon_evidence"`
}
type EndpointCandidate struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Kind   string `json:"kind"`
	// Source co-occurrence does not establish a flag-to-endpoint control relationship.
}
type Asset struct {
	Source   string `json:"source"`
	URL      string `json:"url"`
	FinalURL string `json:"final_url"`
	Status   int    `json:"status"`
}

var sdkCalls = regexp.MustCompile(`\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*(variation|variationDetail|isEnabled|isOn|isOff|getFeatureValue|checkGate|checkGateSync|getFeatureFlag|isFeatureEnabled|hasFeature)\s*\(\s*["']([^"'\r\n]+)["']`)
var endpointCalls = regexp.MustCompile(`\b(fetch|axios\.(?:get|post|put|patch|delete)|\w+\.open)\s*\(\s*(?:["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*)?["']([^"'\r\n]+)["']`)

func harvestSDKCalls(text, source string, acc *harvestAcc) {
	for _, m := range sdkCalls.FindAllStringSubmatch(text, -1) {
		acc.addFlag(m[3], "", source+":sdk-call:"+m[1]+"."+m[2])
	}
}
func evidenceKind(source string) string {
	switch {
	case strings.Contains(source, ":sdk-call:"):
		return "sdk-call"
	case strings.HasSuffix(source, "-api"), strings.HasSuffix(source, "-evalx"), strings.HasPrefix(source, "statsig-"), source == "posthog-decide", source == "flagsmith-identities", source == "configcat":
		return "provider-response"
	case strings.Contains(source, ":json"), strings.Contains(source, ":window"):
		return "structured-data"
	default:
		return "name-heuristic"
	}
}
func evidenceRank(kind string) int {
	switch kind {
	case "provider-response":
		return 3
	case "structured-data":
		return 2
	case "sdk-call":
		return 1
	default:
		return 0
	}
}
func recordFlag(existing Flag, key, val, source string, on *bool) Flag {
	ev := Evidence{Source: source, Kind: evidenceKind(source), Value: val}
	if existing.Key == "" {
		existing = Flag{Key: key, Value: val, Source: source, On: on}
	}
	duplicate := false
	for _, old := range existing.Evidence {
		if old == ev {
			duplicate = true
			break
		}
	}
	if !duplicate {
		existing.Evidence = append(existing.Evidence, ev)
	}
	sort.Slice(existing.Evidence, func(i, j int) bool {
		a, b := existing.Evidence[i], existing.Evidence[j]
		return a.Source+"\x00"+a.Value < b.Source+"\x00"+b.Value
	})
	if evidenceRank(ev.Kind) > evidenceRank(evidenceKind(existing.Source)) || (existing.Value == "" && val != "") {
		existing.Value = val
		existing.Source = source
		existing.On = on
	}
	rank := 0
	for _, e := range existing.Evidence {
		if r := evidenceRank(e.Kind); r > rank {
			rank = r
		}
	}
	existing.Confidence = "low"
	if rank > 0 {
		existing.Confidence = "medium"
	}
	if rank > 1 {
		existing.Confidence = "high"
	}
	values := map[string]bool{}
	for _, e := range existing.Evidence {
		if e.Value != "" {
			values[e.Value] = true
		}
	}
	existing.ConflictingValues = len(values) > 1
	if existing.ConflictingValues {
		existing.On = nil
	}
	return existing
}
func unambiguousValue(f Flag) (string, bool) {
	values := map[string]bool{}
	for _, e := range f.Evidence {
		if e.Value != "" {
			values[e.Value] = true
		}
	}
	if len(f.Evidence) == 0 && f.Value != "" {
		values[f.Value] = true
	}
	if len(values) != 1 {
		return "", false
	}
	for v := range values {
		return v, true
	}
	return "", false
}
func diffValues(auth, anon []Flag) []ValueChange {
	other := map[string]Flag{}
	for _, f := range anon {
		other[f.Key] = f
	}
	out := []ValueChange{}
	for _, f := range auth {
		a, ok := unambiguousValue(f)
		if !ok {
			continue
		}
		g, ok := other[f.Key]
		if !ok {
			continue
		}
		b, ok := unambiguousValue(g)
		if ok && a != b {
			out = append(out, ValueChange{f.Key, a, b, f.Evidence, g.Evidence})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
func extractEndpoints(text, source, pageURL string) []EndpointCandidate {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []EndpointCandidate
	for _, m := range endpointCalls.FindAllStringSubmatch(text, -1) {
		raw := m[2]
		if strings.ContainsAny(raw, "{}<>") {
			continue
		}
		u, err := base.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment = ""
		if seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		out = append(out, EndpointCandidate{u.String(), source, "literal-http-call"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}
