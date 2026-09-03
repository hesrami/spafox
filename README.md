# SPAFox

**A React/Next.js-aware secret hunter for single-page applications.**

SPAFox is a quick-and-dirty tool born from equal parts necessity and curiosity, necessity from an assessment where I had to test 600+ target domains most of which ran NextJS apps, and curiosity as a playground for Spec-Driven Development in open-source offensive tooling.

It crawls a live SPA, follows Webpack chunks and dynamic imports to reach lazy-loaded JS bundles most scanners miss, and audits both external files and inline <script> blocks against a library of secret and framework exposure patterns. Results are exported to the console, raw JSON, or a styled HTML report, and built-in batching lets you run entire bug-bounty or pentest scope lists in one go.

![screenshot](docs/screenshot.png)


## Why SPAFox

Most JS-secret tools expect you to hand them a list of `.js` files. SPAFox does the discovery itself: it fetches the target's HTML, pulls out every script reference (`<script src>`, `modulepreload`, sourcemap comments), then recursively follows webpack chunk-loading calls and `import()` statements up to a configurable depth — so it reaches code that's only loaded after the initial bundle, without you needing to enumerate it by hand.

It also ships detectors written specifically for SPA frameworks, not just generic secret regexes:

- `__NEXT_DATA__` runtime env config exposed in the page
- `window.__reactRouterContext` leaking auth/session data
- `REACT_APP_*`, `NEXT_PUBLIC_*`, `VUE_APP_*`, `GATSBY_*` env vars baked into the client bundle
- GraphQL endpoints with auth tokens nearby
- `postMessage` listeners with no origin check

## How it works

1. Fetch the target page
2. Extract JS references (script tags, modulepreload links, sourcemap URLs)
3. Recursively fetch and follow webpack chunk / dynamic-import references, `--depth` levels deep
4. Regex-scan every file and inline script against ~20 secret patterns
5. Deduplicate and write console / JSON / HTML reports, grouped by severity

## Detection coverage

**General:** Bearer tokens, Basic Auth, generic API keys, JWTs, OAuth client secrets, AWS access/secret keys, Firebase config, Stripe live & test keys, SendGrid keys, Slack tokens, GitHub PATs, PEM private key blocks, hardcoded passwords, credentials embedded in URLs, S3 bucket URLs, internal IPs

**SPA/framework-specific:** Next.js runtime config, React Router context leaks, framework env-var leaks, GraphQL+auth proximity, unguarded `postMessage` handlers

## Example Output

Run against a target with hardcoded secrets in its production JS bundle:

```
$ python3 spafox.py -u https://target.example/

┌─┐┌─┐┌─┐┌─┐┌─┐─┐ ┬
└─┐├─┘├─┤├┤ │ │┌┴┬┘
└─┘┴  ┴ ┴└  └─┘┴ └─
    v3.0.0 :: SPA Secret Hunter + Route Intel
    secrets | routes | directories | cloud keys
    author: rami (Daniel J.)

[+] Starting crawl of https://target.example.com
    Scanning 32 inline scripts
[+] Crawl complete. 25 JS files scanned.
    5 secrets | 5 routes | 0 directories
[+] JSON report: spafox_output/https_target.example.com_.json
[+] HTML report: spafox_output/https_target.example.com_.html


SECRETS
──────────────────────────────────────────────────────────────────────

  CRITICAL (1)
    [aws_access_key] AKIAIOSFODNN7EXAMPLE
        → https://target.example/static/app.config.js:8  


  HIGH (3)
    [generic_secret_assignment] token:"skxzxx50V4zxeuxuMx9xOxxiIAPEtHeGO08...xUvlE40oxFw5WuOuNb3"
        → https://target.example/static/obj/web-common-sg/site/public/_next/static/chunks/8761-54076d176bfhe05a.js:1  
    [api_key_generic] apiKey: "sk_live_51H8xJ2example00000000"
        → https://target.example/static/app.config.js:5
    [generic_secret_assignment] apiKey: "sk_live_51H8xJ2example00000000"
        → https://target.example/static/app.config.js:5
    [generic_secret_assignment] token: "skcms_example_token_do_not_use_0000"
        → https://target.example/static/app.config.js:6

ROUTES
──────────────────────────────────────────────────────────────────────

    [fetch_endpoint] /api/v1/ip/location
        → https://target.example.com/static/obj/web-common-sg/site/public/_next/static/chunks/app/layout-2a5fcge456b2a976.js:1
    [api_path_string] /api/v1/ip/location
        → https://target.example/static/obj/web-common-sg/site/public/_next/static/chunks/app/layout-2a5fcge456b2a976.js:1
    [url_constructor] https://target.example.com
        → https://target.example.com/static/obj/web-common-sg/site/public/_next/static/chunks/app/layout-2a5fcge456b2a976.js:1
    [fetch_endpoint] /api/v1/website/agent/config
        → https://target.example.com/static/obj/web-common-sg/site/public/_next/static/chunks/8388-2b5fcqe456b2a576.js:1
    [api_path_string] /api/v1/website/agent/config
        → https://target.example.com/static/obj/web-common-sg/site/public/_next/static/chunks/8388-2b5fcqe456b2a576.js:1

──────────────────────────────────────────────────────────────────────
  Summary: 21 JS files | 5 secrets | 5 routes | 0 directories
```

*(values above are synthetic — dummy AWS/Stripe-format strings for demonstration, not real credentials)*

SPAFox has been used in active bug bounty and pentest engagements against production Next.js/React targets, surfacing hardcoded credentials and vulnerable API routes in live client-side bundles.

## Install

```bash
git clone https://github.com/hesrami/spafox.git
cd spafox
pip install -r requirements.txt
```

## Usage

```bash
# Single target
python3 spafox.py -u https://example.com/

# Batch scan a list of targets
python3 spafox.py -f targets.txt -o reports/ --threads 20

# Deep crawl (follow webpack chunks 3 levels deep), through a proxy
python3 spafox.py -u https://example.com -d 3 --proxy http://127.0.0.1:8080
```

| Flag | Description | Default |
|---|---|---|
| `-u, --url` | Single target URL | — |
| `-f, --file` | File of target URLs, one per line | — |
| `-o, --output` | Output directory | `spa_recon_output` |
| `-t, --threads` | Concurrent threads | `10` |
| `-d, --depth` | JS chunk crawl depth | `2` |
| `--proxy` | HTTP proxy | — |
| `--headers` | Custom headers as a JSON string | — |

Batch mode writes a JSON + HTML report per target, a `MASTER_REPORT` combining all findings, and an `unreachable_targets.txt` log for dead hosts so they don't clutter the results.

## How SPAFox compares

| | SPAFox | [jsleak](https://github.com/byt3hx/jsleak) | [jsluice](https://github.com/BishopFox/jsluice) |
|---|---|---|---|
| Discovers JS files itself (crawls a live target, follows webpack chunks) | ✅ | Operates on files/URLs you supply | Operates on files you supply |
| SPA framework-specific detectors (Next.js, React Router, env-var leaks) | ✅ | Generic patterns | Generic patterns |
| Detection method | Regex | Regex | AST (tree-sitter) — fewer false positives |
| Multi-target batch mode with master report | ✅ | — | — |
| Built-in HTML report | ✅ | — | — |

Worth being upfront about the trade-off: jsluice's tree-sitter approach understands JS structure, so it can match values by how they're *used* rather than just how they look, which generally means fewer false positives than a regex engine like SPAFox's or jsleak's. SPAFox's edge is the live-crawl + SPA-specific detection, not raw match precision.

## Limitations

- Regex-based detection — expect some false positives, especially on minified/obfuscated bundles. Triage findings manually, especially via the HTMl report view which I highly recommend.
- No live validation of discovered secrets (e.g. no calls to confirm a key is actually active).
- Sourcemap references are fetched and scanned as text but not parsed back into original source files yet.
- This tool only has features I needed at the moment of urgency for large scale JS file audits, you're welcome to fork.

## Disclaimer

SPAFox is intended for authorized security testing and bug bounty work only. Scanning targets without permission may be illegal in your jurisdiction. The author accepts no liability for misuse but have fun and reach out if it's of any help to you on your engagement/hunting ;)

## Author

rami/akanbi (Daniel J.)
