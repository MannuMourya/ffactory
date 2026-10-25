package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSDKCallsAndEvidence(t *testing.T) {
	acc := newHarvest()
	harvest(`ldclient.variation("checkout-v2",false); growthbook.isOn("ai"); statsig.checkGate("new-editor"); const FEATURE_GUESS = 1;`, "js-00.js", acc)
	for _, key := range []string{"checkout-v2", "ai", "new-editor"} {
		f, ok := acc.flags[key]
		if !ok || f.Confidence != "medium" || len(f.Evidence) != 1 {
			t.Fatalf("%s: %+v", key, f)
		}
	}
	if acc.flags["FEATURE_GUESS"].Confidence != "low" {
		t.Fatal("heuristic overstated")
	}
	acc.addFlagVal("checkout-v2", "true", "document:json:flags", nil)
	acc.addFlagVal("checkout-v2", "false", "launchdarkly-evalx", nil)
	f := acc.flags["checkout-v2"]
	if !f.ConflictingValues || f.On != nil || len(f.Evidence) != 3 {
		t.Fatalf("lost contradictory evidence: %+v", f)
	}
	acc.addFlagVal("checkout-v2", "false", "launchdarkly-evalx", nil)
	if len(acc.flags["checkout-v2"].Evidence) != 3 {
		t.Fatal("duplicate evidence")
	}
}

func TestValueComparison(t *testing.T) {
	auth, anon := newHarvest(), newHarvest()
	for _, item := range []struct{ key, a, b string }{{"checkout", "true", "false"}, {"theme", `"dark"`, `"light"`}, {"same", "true", "true"}, {"ambiguous", "true", "false"}} {
		auth.addFlag(item.key, item.a, "document:json:flags")
		anon.addFlag(item.key, item.b, "document:json:flags")
	}
	auth.addFlag("ambiguous", "false", "js-00.js:json:flags")
	auth.addFlag("unknown", "", "js-00.js:sdk-call:ld.variation")
	anon.addFlag("unknown", "true", "document:json:flags")
	changes := diffValues(auth.sortedFlags(), anon.sortedFlags())
	if len(changes) != 2 || changes[0].Key != "checkout" || changes[1].Key != "theme" {
		t.Fatalf("bad differences: %+v", changes)
	}
}

func TestEndpointCandidates(t *testing.T) {
	got := extractEndpoints(`fetch("/api/export?format=pdf"); axios.post("https://api.example.org/v2/jobs"); xhr.open("GET", "./account"); fetch("javascript:alert(1)"); const unrelated="/admin";`, "js-00.js", "https://app.example.org/product/")
	if len(got) != 3 {
		t.Fatalf("unexpected candidates: %+v", got)
	}
	if got[1].URL != "https://app.example.org/api/export?format=pdf" || got[2].URL != "https://app.example.org/product/account" {
		t.Fatalf("incorrect browser URL resolution: %+v", got)
	}
}

func TestResearchScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bundle.js" {
			fmt.Fprint(w, `client.variation("checkout-v2", false); fetch("/api/export");`)
			return
		}
		value := "false"
		if r.Header.Get("Authorization") != "" {
			value = "true"
		}
		fmt.Fprintf(w, `<script type="application/json">{"flags":{"checkout-v2":%s}}</script><script src="/bundle.js"></script>`, value)
	}))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.URL = srv.URL
	cfg.CacheDir = t.TempDir()
	cfg.Bearer = "secret"
	cfg.CompareAnon = true
	cfg.NoProbe = true
	rep, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ValueChanges) != 1 || rep.ValueChanges[0].Key != "checkout-v2" {
		t.Fatalf("missing value change: %+v", rep.ValueChanges)
	}
	if len(rep.Endpoints) != 1 || len(rep.Assets) != 2 || rep.Assets[1].URL != srv.URL+"/bundle.js" {
		t.Fatalf("lost provenance: %+v", rep)
	}
	if len(rep.Flags[0].Evidence) < 2 {
		t.Fatal("lost evidence sources")
	}
}
