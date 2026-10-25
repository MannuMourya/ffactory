# ffactory

It finds **hidden features**, **feature-flag SaaS**, **eval/config APIs**, and **sibling products** on a target origin. It accepts a browser session, a bearer token, or it can log in itself.

This is an asset-discovery tool for authorized bug bounty / VDP work. It does not exploit anything. A flag name is not a finding.

```text
corporate homepage  →  often a brochure
product origin      →  mail.app / docs.app / go.app / id.app   ← scan here
session + user-id   →  staff / plan / beta treatments
```

---

## Install from GitHub (`go install`)

Needs [Go 1.22+](https://go.dev/dl/).

```bash
# latest commit on default branch
go install github.com/mannumourya/ffactory@latest

# or a tagged release
go install github.com/mannumourya/ffactory@v0.1.0
```

The binary lands in `$(go env GOPATH)/bin` (usually `~/go/bin`). Put that on `PATH`:

```bash
echo 'export PATH="$(go env GOPATH)/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

ffactory help
```

### One-shot without installing

```bash
go run github.com/mannumourya/ffactory@latest scan -u https://factory.app -o out.json
```

### Build from a clone

```bash
git clone https://github.com/mannumourya/ffactory.git
cd ffactory
go build -o ffactory .
./ffactory help
```

---

### 1. Confirm the module path matches the repo

`go.mod` must be exactly:

```go
module github.com/mannumourya/ffactory

go 1.22
```

## Manual

### What it does

On `ffactory scan -u URL`:

1. Attaches cookies / headers, or POSTs `--login-url`
2. Fetches the first HTML document (flags are often inlined there so the SPA does not flicker)
3. Follows `<script src>`, `modulepreload`, and custom config scripts (`type="x-superhuman/config"` → `pageJs`)
4. Fingerprints LaunchDarkly, GrowthBook, Unleash, Flagsmith, Statsig, Optimizely, Split, ConfigCat, PostHog, plus homegrown `window.ShData` / `__NEXT_DATA__` blobs
5. Extracts flag keys, default values, client keys, eval URLs, sibling hosts
6. Unless `--no-probe`, hits discovered eval APIs **as `--user-id` / `--attr`**
7. Writes HTML + JS to `--cache-dir` for grep
8. Optional `--compare-anon` runs a second logged-out pass and diffs keys

### Commands

| Command | Purpose |
|---|---|
| `ffactory scan -u URL …` | Hunt flags + assets |
| `ffactory login --login-url … --save-session s.json` | Login only, persist jar |
| `ffactory help` | Usage |
| `ffactory -u URL …` | Shorthand for `scan` |

### Auth (any mix)

| Flag | Meaning |
|---|---|
| `--cookie "a=b; c=d"` | Raw `Cookie` header from DevTools |
| `--cookie-file path` | Same, from a file |
| `-H, --header "Name: value"` | Repeatable extra header |
| `--bearer TOKEN` | Sets `Authorization: Bearer TOKEN` |
| `--session s.json` | Reload cookies + headers from a previous run |
| `--save-session s.json` | Write them after login/scan |
| `--login-url URL` | POST here before the scan |
| `--login-json '{…}'` | JSON body for that POST |
| `--login-user` / `--login-pass` | Form fields (defaults `email` / `password`) |
| `--login-user-field` / `--login-pass-field` | Override those field names |
| `--login-extra key=value` | Extra form/JSON field, repeatable |
| `--user-id ID` | Targeting key sent to eval APIs |
| `--attr key=value` | Extra targeting attribute, repeatable |

If login is a CSRF / SSO maze, do not fight the client. Grab the cookie from the browser and pass `--cookie`.

### Scan options

| Flag | Default | Meaning |
|---|---|---|
| `-u, --url` | required | Document to fetch |
| `-o, --out` | — | JSON report path |
| `--cache-dir` | `/tmp/ffactory-cache` | Saved HTML + JS |
| `--js-limit` | `30` | Max JS files to pull |
| `--timeout` | `20` | Per-request seconds |
| `--insecure` | off | Skip TLS verify |
| `--no-probe` | off | Extract only, do not call eval APIs |
| `--compare-anon` | off | Second pass with no session, print AUTH-ONLY / ANON-ONLY keys |

### Workflow

**1. Classify the factory, not the brochure**

`nasa.gov` is a comms site. You will get CSS `toggle-*` noise and zero eval APIs. Stop.

`superhuman.com` is a marketing Next app. The factory is `mail.superhuman.com`, `docs.superhuman.com`, `go.superhuman.com`, `id.superhuman.com`. Scan those origins.

**2. Anonymous pass on the product host**

```bash
ffactory scan -u https://mail.example.com \
  --js-limit 20 \
  --cache-dir /tmp/ff-mail \
  -o mail-anon.json
```

**3. Authenticated pass**

```bash
ffactory scan -u https://mail.example.com \
  --cookie "session=…" \
  --user-id 1842 \
  --attr email=you@org.com \
  --compare-anon \
  --save-session mail.session.json \
  --cache-dir /tmp/ff-mail-auth \
  -o mail-auth.json
```

Login API instead of a cookie:

```bash
ffactory scan -u https://factory.app \
  --login-url https://factory.app/api/login \
  --login-json '{"email":"hunter@x.com","password":"…"}' \
  --user-id 1842 \
  --compare-anon \
  --save-session factory.session.json \
  -o factory-auth.json
```

Reuse the jar later:

```bash
ffactory scan -u https://factory.app --session factory.session.json --user-id 1842 -o day2.json
```

**4. Read the summary, then grep the cache**

```bash
jq '.flags[] | select(.key|test("admin|staff|beta|ai|wallet|agent|import";"i"))' mail-auth.json
rg -n 'TOGGLE_AI_TRIAGE|sh_go_1_0_launch' /tmp/ff-mail-auth
```

**5. Flip only the document in a proxy**

Flags must be present on first paint. Restrict match-replace to `Content-Type: text/html` (or `Accept: text/html`). Do not flip `false→true` on JSON XHRs — you will break auth.

Isolate one jewel key, then hit every new endpoint as user A, user B, and anon. Client flags only reveal UI and JS. The server endpoints you discovered are the real target.

### JSON report shape

```json
{
  "target": "https://mail.example.com",
  "authenticated": true,
  "document_status": 200,
  "platforms": ["launchdarkly", "statsig"],
  "client_keys": [{ "platform": "statsig", "key": "client-…", "source": "document" }],
  "eval_urls": [{ "platform": "launchdarkly", "url": "https://clientstream.launchdarkly.com", "source": "js-01.js" }],
  "flags": [{ "key": "sh_go_1_0_launch", "value": "gate:enabled_1", "source": "document:json:treatments:statsig" }],
  "secondary_hosts": ["admin.example.com", "staging.example.io"],
  "auth_only_flags": ["isStaffTools"],
  "anon_only_flags": [],
  "notes": []
}
```

### Platforms probed

| Platform | How it is found | Probe |
|---|---|---|
| LaunchDarkly | client-side id, `*.launchdarkly.com` | `evalx/{id}/contexts/{b64}` |
| GrowthBook | `sdk-…`, `cdn.growthbook.io` | `/api/features/{key}`, `/api/eval/{key}` |
| Unleash | host + `/api/frontend` | discovery only |
| Flagsmith | env key | `/api/v1/identities/?identifier=` |
| Statsig | `client-` key ≥ 20 chars | `/v1/initialize` |
| Optimizely | datafile URL | GET datafile |
| ConfigCat | `cdn.configcat.com` | GET config JSON |
| PostHog | `phc_…` | `/decide/?v=3` |
| Homegrown | `window.ShData`, `__NEXT_DATA__`, `FEATURE_*` | none (proxy flip) |

`--user-id` is used by the implemented identity probes. Generic `--attr` targeting is currently supported by GrowthBook and LaunchDarkly only.

---

## Legal

Only run this against hosts you are allowed to test (bug bounty / VDP / written contract). Respect scope, rate limits, and out-of-scope assets (`staging.` is not automatically in scope). Do not commit cookies, session files, or report JSON that contains tokens.

## Validation and credential handling

Run the local regression suite with:

```bash
go test -race -cover ./...
go vet ./...
go build ./...
```

Tests use local HTTP fixtures, including login/session reload, credential isolation,
authenticated/anonymous comparisons, script limits, extraction, and API error responses.
They do not certify compatibility with every live provider or a target's login flow.

Supplied headers (including bearer tokens and raw Cookie headers) are sent only to
the exact target origin. Cross-origin redirects strip supplied headers; provider
API keys are scoped to their individual request. Cookie-jar cookies follow normal
cookie domain/path rules. Login-only mode uses the login URL as its session origin.
New saved sessions retain cookie paths, secure/expiry attributes, and the originating
URL, and reject reuse against a different origin. Explicit CLI headers override saved
headers. Legacy sessions lack origin metadata; regenerate them with this version.

Session files, reports, and cached responses are written with owner-only permissions.
The anonymous cache is stored in `CACHE_DIR/anon/`; it does not replace the authenticated
cache. Comparison uses document/bundle flag keys on both sides, excluding provider
probe results. `authenticated` indicates that credentials/login were supplied; it is
not proof that the server accepted them. A successful login HTTP response likewise
does not guarantee an authenticated application session.

`--js-limit 0` disables bundle fetching; the limit counts attempted bundle requests,
including failures. Save/cache errors are reported instead of silently ignored.

Provider limitations: Unleash and Split currently support discovery only; Unleash
frontend probing is not implemented. ConfigCat parses v6 `f` settings maps.
Generic targeting attributes are currently used by GrowthBook and LaunchDarkly;
other provider targeting support is incomplete. Self-hosted/region-specific APIs
may need additional endpoint configuration.

## Evidence-driven feature research

The scanner produces discovery leads for investigating hidden functionality,
plan/role targeting, and client/server authorization boundaries. It does not
validate vulnerabilities or infer exploitability from client-side configuration.

Reports now include:

- `flags[].evidence`: all distinct observed source/value pairs, classified as
  SDK call, structured data, provider response, or name heuristic.
- `flags[].confidence`: confidence in the discovery evidence, **not severity**.
  Name-only matches are low; SDK-shaped calls are medium; structured data and
  provider responses are high. Structured data can still be ordinary config.
- `flags[].conflicting_values`: contradictory observations are retained rather
  than silently discarded. The legacy `value` is representative, not an effective
  runtime evaluation. An SDK call's default argument is not treated as its result.
- `value_changes`: shared keys with different unambiguous observed values between
  the credentialed and anonymous document/bundle passes. These include boolean
  and variant changes. Conflicting or unknown values are excluded.
- `assets`: maps cached source names to requested/final URLs and HTTP status.
- `endpoint_candidates`: literal fetch, axios method, and XHR-open destinations
  with source provenance. These are extracted, not requested. Relative HTTP
  calls resolve against the document URL, as in the browser.

Example:

```bash
ffactory scan -u https://app.example.com --session own-account.json \
  --compare-anon --no-probe --cache-dir ./research-cache -o research.json
jq '.value_changes' research.json
jq '.flags[] | select(.confidence != "low") | {key, evidence, conflicting_values}' research.json
jq '.endpoint_candidates, .assets' research.json
```

Use the source evidence to inspect the surrounding code and establish whether a
flag actually gates an endpoint or UI route. Endpoint/flag co-occurrence in a
bundle alone does not establish that relationship. Verify any resulting access
hypothesis separately with your authorized accounts and the server's responses.

Static analysis limitations: JavaScript is not executed; computed keys, runtime
imports, template-built endpoints, and dynamically loaded values may be missed.
SDK-shaped method names can also belong to unrelated objects. Comments and dead
code can be matched. A difference between passes can reflect experiments, time,
or personalization rather than a role boundary; repeat before drawing conclusions.

### Blocked or challenged documents

A 403 with a “Just a moment...” page means the server returned a challenge,
not the application. ffactory uses an HTTP client and does not execute JavaScript
or solve browser challenges. It cannot claim to have scanned the application in
that situation, even when the challenge itself returns HTTP 200.

Reports include `outcome`: `completed`, `blocked`, `http_error`, or `empty`.
Unusable documents are cached for inspection, but are not harvested or followed
for scripts/probes. The CLI exits with status 1 after writing the requested JSON
report. It does not print zero-result application findings for a blocked scan.
If only the anonymous comparison is challenged, the main scan remains completed
and the report notes that comparison is unavailable.

Confirm that the intended URL is accessible in your browser. A legitimate browser
session may help with ordinary authentication, but challenge clearance can depend
on browser execution and connection properties; copying cookies is not a reliable
solution for this HTTP client. A completed scan also does not mean every runtime
asset or feature was discoverable statically.
