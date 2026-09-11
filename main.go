// ffactory — Feature Factory asset + flag scanner.
// Finds hidden features, flag SaaS, eval APIs, and sibling products.
// Accepts a browser session, raw headers, or a login request.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		// allow `ffactory -u ...` as shorthand for scan
		if strings.HasPrefix(os.Args[1], "-") {
			runScan(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `ffactory — find Feature Factory assets (flags, eval APIs, sibling products)

USAGE
  ffactory scan  -u https://factory.app [auth] [options]
  ffactory login --login-url https://factory.app/api/login --login-json '{...}' --save-session s.json

AUTH (any combination)
  --cookie "name=value; name2=value2"     raw Cookie header from the browser
  --cookie-file path                      raw cookie header or name=value per line
  -H, --header "Name: value"              repeatable
  --bearer TOKEN                          sets Authorization: Bearer TOKEN
  --session path.json                     load cookies + headers from a previous run
  --save-session path.json                write cookies + headers after login/scan
  --login-url URL                         POST here before the scan
  --login-json '{"email":"...","password":"..."}'
  --login-user USER  --login-pass PASS    form fields (defaults email / password)
  --login-user-field  --login-pass-field  override form field names
  --login-extra key=value                 extra form/json field, repeatable
  --user-id ID                            targeting identity for eval APIs
  --attr key=value                        extra targeting attribute, repeatable

SCAN
  -u, --url URL                           target document (required)
  -o, --out FILE                          write JSON report
  --cache-dir DIR                         save HTML + JS for grepping (default /tmp/ffactory-cache)
  --js-limit N                            max JS bundles to fetch (default 30)
  --timeout SEC                           per-request timeout (default 20)
  --insecure                              skip TLS verify
  --no-probe                              extract only, do not hit eval APIs
  --compare-anon                          also fetch logged-out and diff flags

Examples
  ffactory scan -u https://app.example.com --cookie "session=abc" --user-id 42 -o out.json
  ffactory scan -u https://app.example.com --login-url https://app.example.com/api/login \
      --login-json '{"email":"a@b.c","password":"x"}' --user-id 42 --compare-anon
`)
}

func runScan(args []string) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	bindCommon(fs, cfg)
	fs.Parse(args)

	if cfg.URL == "" {
		fmt.Fprintln(os.Stderr, "error: -u/--url is required")
		os.Exit(2)
	}

	rep, err := Scan(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}
	printSummary(rep)
	if cfg.Out != "" {
		if err := writeJSON(cfg.Out, rep); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", cfg.Out, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\nJSON written to %s\n", cfg.Out)
	}
}

func runLogin(args []string) {
	cfg := defaultConfig()
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	bindCommon(fs, cfg)
	fs.Parse(args)
	if cfg.LoginURL == "" {
		fmt.Fprintln(os.Stderr, "error: --login-url is required")
		os.Exit(2)
	}
	if cfg.SaveSession == "" {
		fmt.Fprintln(os.Stderr, "error: --save-session is required for login")
		os.Exit(2)
	}
	c, err := newClient(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
	if err := c.doLogin(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	if err := c.saveSession(cfg.SaveSession); err != nil {
		fmt.Fprintf(os.Stderr, "save session: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "session saved to %s (%d cookies)\n", cfg.SaveSession, c.cookieCount())
}

func bindCommon(fs *flag.FlagSet, cfg *Config) {
	fs.StringVar(&cfg.URL, "u", cfg.URL, "")
	fs.StringVar(&cfg.URL, "url", cfg.URL, "")
	fs.StringVar(&cfg.Out, "o", cfg.Out, "")
	fs.StringVar(&cfg.Out, "out", cfg.Out, "")
	fs.StringVar(&cfg.Cookie, "cookie", cfg.Cookie, "")
	fs.StringVar(&cfg.CookieFile, "cookie-file", cfg.CookieFile, "")
	fs.StringVar(&cfg.Bearer, "bearer", cfg.Bearer, "")
	fs.StringVar(&cfg.Session, "session", cfg.Session, "")
	fs.StringVar(&cfg.SaveSession, "save-session", cfg.SaveSession, "")
	fs.StringVar(&cfg.LoginURL, "login-url", cfg.LoginURL, "")
	fs.StringVar(&cfg.LoginJSON, "login-json", cfg.LoginJSON, "")
	fs.StringVar(&cfg.LoginUser, "login-user", cfg.LoginUser, "")
	fs.StringVar(&cfg.LoginPass, "login-pass", cfg.LoginPass, "")
	fs.StringVar(&cfg.LoginUserField, "login-user-field", cfg.LoginUserField, "")
	fs.StringVar(&cfg.LoginPassField, "login-pass-field", cfg.LoginPassField, "")
	fs.StringVar(&cfg.UserID, "user-id", cfg.UserID, "")
	fs.StringVar(&cfg.CacheDir, "cache-dir", cfg.CacheDir, "")
	fs.IntVar(&cfg.JSLimit, "js-limit", cfg.JSLimit, "")
	fs.IntVar(&cfg.TimeoutSec, "timeout", cfg.TimeoutSec, "")
	fs.BoolVar(&cfg.Insecure, "insecure", cfg.Insecure, "")
	fs.BoolVar(&cfg.NoProbe, "no-probe", cfg.NoProbe, "")
	fs.BoolVar(&cfg.CompareAnon, "compare-anon", cfg.CompareAnon, "")
	fs.Var(&cfg.Headers, "H", "")
	fs.Var(&cfg.Headers, "header", "")
	fs.Var(&cfg.Attrs, "attr", "")
	fs.Var(&cfg.LoginExtra, "login-extra", "")
}

func defaultConfig() *Config {
	return &Config{
		CacheDir:       "/tmp/ffactory-cache",
		JSLimit:        30,
		TimeoutSec:     20,
		LoginUserField: "email",
		LoginPassField: "password",
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func printSummary(r *Report) {
	fmt.Printf("target          %s\n", r.Target)
	fmt.Printf("authenticated   %v\n", r.Authenticated)
	fmt.Printf("status          %d\n", r.DocumentStatus)
	fmt.Printf("title           %s\n", r.Title)
	fmt.Printf("platforms       %s\n", strings.Join(r.Platforms, ", "))
	fmt.Printf("client_keys     %d\n", len(r.ClientKeys))
	fmt.Printf("eval_urls       %d\n", len(r.EvalURLs))
	fmt.Printf("flags           %d\n", len(r.Flags))
	fmt.Printf("secondary_hosts %d\n", len(r.SecondaryHosts))
	fmt.Printf("product_names   %s\n", strings.Join(r.ProductNames, ", "))
	fmt.Printf("js_bundles      %d\n", len(r.JSBundles))
	if len(r.ClientKeys) > 0 {
		fmt.Println("\nclient keys")
		for _, k := range r.ClientKeys {
			fmt.Printf("  [%s] %s\n", k.Platform, k.Key)
		}
	}
	if len(r.EvalURLs) > 0 {
		fmt.Println("\neval / config URLs")
		for _, u := range r.EvalURLs {
			fmt.Printf("  [%s] %s\n", u.Platform, u.URL)
		}
	}
	if len(r.Flags) > 0 {
		fmt.Println("\nflags (first 60)")
		n := 0
		for _, f := range r.Flags {
			fmt.Printf("  %-40s %-10s  %s\n", f.Key, f.Value, f.Source)
			n++
			if n >= 60 {
				fmt.Printf("  … %d more\n", len(r.Flags)-60)
				break
			}
		}
	}
	if len(r.SecondaryHosts) > 0 {
		fmt.Println("\nsecondary hosts / factory siblings")
		for _, h := range r.SecondaryHosts {
			fmt.Printf("  %s\n", h)
		}
	}
	if len(r.AnonOnlyFlags) > 0 || len(r.AuthOnlyFlags) > 0 {
		fmt.Println("\nanon vs auth diff")
		for _, k := range r.AuthOnlyFlags {
			fmt.Printf("  AUTH-ONLY  %s\n", k)
		}
		for _, k := range r.AnonOnlyFlags {
			fmt.Printf("  ANON-ONLY  %s\n", k)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Println("\nnotes")
		for _, n := range r.Notes {
			fmt.Printf("  - %s\n", n)
		}
	}
	fmt.Printf("\nscanned at %s\n", r.ScannedAt.Format(time.RFC3339))
}
