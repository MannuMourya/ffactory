package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		body, outcome string
	}{
		{"reported challenge", 403, "<title>Just a moment...</title>", "blocked"},
		{"challenge with HTTP 200", 200, "<script src='/cdn-cgi/challenge-platform/test.js'></script>", "blocked"},
		{"ordinary forbidden", 403, "<title>Forbidden</title>", "blocked"},
		{"unauthorized", 401, "denied", "blocked"},
		{"rate limited", 429, "slow down", "blocked"},
		{"server error", 503, "unavailable", "http_error"},
		{"empty", 204, "", "empty"},
		{"normal app", 200, "<title>App</title>", "completed"},
		{"title alone not enough", 200, "<title>Just a moment...</title><main>article</main>", "completed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, _ := documentOutcome(tc.status, tc.body)
			if outcome != tc.outcome {
				t.Fatalf("got %q", outcome)
			}
		})
	}
}

func TestBlockedScanDoesNotHarvestOrFetchScripts(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(403)
		fmt.Fprint(w, `<title>Just a moment...</title><script src="/challenge.js"></script><script>window.__FLAGS__={"flags":{"fakeFeature":true}}</script>`)
	}))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.URL = srv.URL
	cfg.CacheDir = t.TempDir()
	cfg.Bearer = "test"
	cfg.CompareAnon = true
	rep, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != "blocked" || scanExitCode(rep) != 1 || len(rep.Flags) != 0 || hits != 1 {
		t.Fatalf("misreported blocked scan: %+v, hits=%d", rep, hits)
	}
	for _, note := range rep.Notes {
		if strings.Contains(note, "no SaaS") || strings.Contains(note, "session may be stale") {
			t.Fatal(note)
		}
	}
	cached, err := os.ReadFile(filepath.Join(cfg.CacheDir, "document.html"))
	if err != nil || !strings.Contains(string(cached), "Just a moment") {
		t.Fatal("missing cached evidence", err)
	}
}

func TestAnonymousChallengeDoesNotProduceFalseDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			fmt.Fprint(w, `<script src="/cdn-cgi/challenge-platform/test.js"></script>`)
			return
		}
		fmt.Fprint(w, `<script type="application/json">{"flags":{"checkout":true}}</script>`)
	}))
	defer srv.Close()
	cfg := defaultConfig()
	cfg.URL = srv.URL
	cfg.CacheDir = t.TempDir()
	cfg.Bearer = "test"
	cfg.CompareAnon = true
	cfg.NoProbe = true
	rep, err := Scan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcome != "completed" || len(rep.AuthOnlyFlags) != 0 || len(rep.ValueChanges) != 0 {
		t.Fatalf("false diff: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " "), "comparison unavailable: blocked") {
		t.Fatal(rep.Notes)
	}
}
