package main

import (
	"fmt"
	"strings"
)

// Classify the document before extracting application evidence from it.
func documentOutcome(status int, body string) (string, string) {
	lower := strings.ToLower(body)
	title := strings.ToLower(strings.TrimSpace(extractTitle(body)))
	challenge := strings.Contains(lower, "/cdn-cgi/challenge-platform/") ||
		strings.Contains(lower, "_cf_chl_opt") ||
		(title == "just a moment..." && (status == 403 || strings.Contains(lower, "enable javascript and cookies"))) ||
		(strings.Contains(title, "verify you are human") && strings.Contains(lower, "challenge"))
	if challenge {
		return "blocked", "Anti-bot challenge received; application content was not scanned. This HTTP client cannot execute browser challenges. Open the URL in a browser to confirm access; browser clearance cookies alone may not work in this client."
	}
	if status == 401 || status == 403 {
		return "blocked", fmt.Sprintf("HTTP %d access denied; application content was not scanned. Verify the URL and access in your browser. This response does not establish whether authentication is required.", status)
	}
	if status == 429 {
		return "blocked", "HTTP 429 rate limited; application content was not scanned. Wait before retrying."
	}
	if status >= 400 {
		return "http_error", fmt.Sprintf("HTTP %d; application content was not scanned.", status)
	}
	if status == 204 || strings.TrimSpace(body) == "" {
		return "empty", "Empty document response; no application content was available to scan."
	}
	return "completed", ""
}

func scanExitCode(r *Report) int {
	if r.Outcome != "" && r.Outcome != "completed" {
		return 1
	}
	return 0
}
