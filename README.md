# ffactory

Go scanner for [Kapeka's Feature Factory methodology](https://kapeka.dev/blog/exploiting-the-feature-factory).

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

Private repo? Then either make it public, or:

```bash
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
export GOPRIVATE=github.com/mannumourya/ffactory
go install github.com/mannumourya/ffactory@latest
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

## Publish this repo so `go install` works

Do this once on the machine that owns the GitHub account. Replace the org/user if yours is not `mannumourya`.

### 1. Confirm the module path matches the repo

`go.mod` must be exactly:

```go
module github.com/mannumourya/ffactory

go 1.22
```

The main package must live at the **repo root** (this tree). If you nest it under `cmd/ffactory`, people have to install `github.com/mannumourya/ffactory/cmd/ffactory@latest` instead.

### 2. Create the empty GitHub repo

GitHub UI: **New repository** → name `ffactory` → public (required for anonymous `go install`) → do **not** add a README/License (they are already here).

Or:

```bash
gh repo create mannumourya/ffactory --public --source=. --remote=origin
```

### 3. First push

From this directory (`scripts/ffactory` in the skill tree, or a copy of it):

```bash
cd /path/to/ffactory
git init
git add go.mod *.go README.md LICENSE .gitignore
git commit -m "ffactory v0.1.0 — Feature Factory flag scanner"
git branch -M main
git remote add origin git@github.com:mannumourya/ffactory.git
git push -u origin main
```

Do **not** commit the compiled `ffactory` binary or session JSON.

### 4. Tag a version (this is what `@v0.1.0` resolves)

Go modules want semver tags.

```bash
git tag -a v0.1.0 -m "ffactory v0.1.0"
git push origin v0.1.0
```

Proxy cache: https://pkg.go.dev/github.com/mannumourya/ffactory  
First `go install` after a new tag can take a few minutes while proxy.golang.org indexes it. Force a fresh fetch with:

```bash
GOPROXY=direct go install github.com/mannumourya/ffactory@v0.1.0
```

### 5. Later releases

```bash
# bump, commit
git tag -a v0.1.1 -m "ffactory v0.1.1"
git push origin main --tags
```

Anyone can then run:

```bash
go install github.com/mannumourya/ffactory@v0.1.1
```

---

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
| Unleash | host + `/api/frontend` | listed URL |
| Flagsmith | env key | `/api/v1/identities/?identifier=` |
| Statsig | `client-` key ≥ 20 chars | `/v1/initialize` |
| Optimizely | datafile URL | GET datafile |
| ConfigCat | `cdn.configcat.com` | GET config JSON |
| PostHog | `phc_…` | `/decide/?v=3` |
| Homegrown | `window.ShData`, `__NEXT_DATA__`, `FEATURE_*` | none (proxy flip) |

`--user-id` and `--attr` are injected into those eval bodies so targeting rules can fire.

### Live-test notes (2026-09-11)

| Origin | Result |
|---|---|
| `https://www.nasa.gov` | Brochure. Widget `disable_*` noise. No platforms. Kill. |
| `https://www.superhuman.com` | Statsig treatments in `window.ShData`: `sh_go_1_0_launch`, `sh_plans_docs_route`, `csf_consolidated_form` |
| `https://go.superhuman.com` | `FEATURE_DICTATION`, `FEATURE_NOTETAKER`, Grammarly/Coda staging + `mcp-sandbox.staging.codahosted.io` |
| `https://mail.superhuman.com` | Follows `page.js` (~11 MB). Hundreds of `TOGGLE_*` keys, LaunchDarkly stream hosts, `admin.superhuman.com` |

Unauthenticated. A Mail/Docs cookie + `--compare-anon` is the next pass, not another homepage scan.

---

## Legal

Only run this against hosts you are allowed to test (bug bounty / VDP / written contract). Respect scope, rate limits, and out-of-scope assets (`staging.` is not automatically in scope). Do not commit cookies, session files, or report JSON that contains tokens.

## Credit

Methodology: [Kapeka — Exploiting the Feature Factory](https://kapeka.dev/blog/exploiting-the-feature-factory) ([thread](https://x.com/kapeka0/status/2015371668928000209)).
