#!/usr/bin/env python3
"""
SPAFox v3.0: React/Next.js Secret Hunter
Scales across 600+ applications. Handles chunked JS, inline scripts, source maps.
Now with JSleak pattern coverage, API route extraction, and directory enumeration.

Author: Daniel J. | Automation Toolkit For Fun & Profit
"""

import os
import re
import sys
import json
import argparse
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Dict
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VERSION = "3.0.0"

# ─────────────────────────────────────────────────────────────
# ANSI COLORS
# ─────────────────────────────────────────────────────────────
class C:
    CYAN    = "\033[96m"
    GREY    = "\033[90m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"


def print_banner():
    if os.environ.get("NO_BANNER"):
        return
    wordmark = r"""
┌─┐┌─┐┌─┐┌─┐┌─┐─┐ ┬
└─┐├─┘├─┤├┤ │ │┌┴┬┘
└─┘┴  ┴ ┴└  └─┘┴ └─
"""
    banner = f"{C.CYAN}{wordmark}{C.RESET}"
    banner += f"    {C.GREY}v{VERSION} :: SPA Secret Hunter + Route Intel{C.RESET}\n"
    banner += f"    {C.GREY}secrets | routes | directories | cloud keys{C.RESET}\n"
    banner += f"    {C.GREY}author: rami (Daniel J.){C.RESET}\n"
    print(banner)


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    target: str
    file_url: str
    finding_type: str
    match: str
    context: str
    severity: str
    line_number: int = 0
    category: str = "secret"          # secret | route | directory | cloud


@dataclass
class ScanSummary:
    target: str
    js_files_scanned: int = 0
    inline_scripts: int = 0
    secrets_found: int = 0
    routes_found: int = 0
    directories_found: int = 0
    errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# SECRET PATTERNS
# ─────────────────────────────────────────────────────────────
# Merged: SPAFox originals + unique JSleak patterns

SECRET_PATTERNS = {
    # ── Authorization & Session ──
    "bearer_token": {
        "pattern": r'(?i)(?:authorization\s*[:=]\s*["\']?Bearer\s+)([a-zA-Z0-9_\-\.]{20,})',
        "severity": "CRITICAL",
        "description": "Hardcoded Bearer token"
    },
    "basic_auth": {
        "pattern": r'(?i)(?:authorization\s*[:=]\s*["\']?Basic\s+)([a-zA-Z0-9+/=]{10,})',
        "severity": "CRITICAL",
        "description": "Basic Auth credential"
    },
    "api_key_generic": {
        "pattern": r'(?i)(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
        "severity": "HIGH",
        "description": "Generic API Key"
    },
    "jwt_token": {
        "pattern": r'(?i)(?:token|access_token|id_token|refresh_token)\s*[:=]\s*["\'](eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)["\']',
        "severity": "HIGH",
        "description": "JWT Token exposed"
    },
    "oauth_secret": {
        "pattern": r'(?i)(?:client_secret|consumer_secret|app_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
        "severity": "CRITICAL",
        "description": "OAuth Client Secret"
    },

    # ── Cloud & Service Keys ──
    "aws_access_key": {
        "pattern": r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',
        "severity": "CRITICAL",
        "description": "AWS Access Key ID"
    },
    "aws_secret_key": {
        "pattern": r'(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key"
    },
    "aws_session_token": {
        "pattern": r'(?i)aws_session_token["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{16,}',
        "severity": "HIGH",
        "description": "AWS Session Token"
    },
    "firebase_key": {
        "pattern": r'(?i)(?:apiKey|databaseURL|projectId)\s*:\s*"(AIza[0-9A-Za-z_\-]{35})"',
        "severity": "HIGH",
        "description": "Firebase configuration key"
    },
    "firebase_config_block": {
        "pattern": r'(?i)firebase\s*:\s*\{[^}]*(?:apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId)[^}]*\}',
        "severity": "MEDIUM",
        "description": "Firebase config block exposed"
    },
    "stripe_key": {
        "pattern": r'(sk_live_[a-zA-Z0-9]{24,})|(pk_live_[a-zA-Z0-9]{24,})',
        "severity": "CRITICAL",
        "description": "Stripe Live Key"
    },
    "stripe_test_key": {
        "pattern": r'(sk_test_[a-zA-Z0-9]{24,})|(pk_test_[a-zA-Z0-9]{24,})',
        "severity": "MEDIUM",
        "description": "Stripe Test Key"
    },
    "sendgrid_key": {
        "pattern": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "severity": "CRITICAL",
        "description": "SendGrid API Key"
    },
    "slack_token": {
        "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
        "severity": "HIGH",
        "description": "Slack Token"
    },
    "slack_webhook": {
        "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        "severity": "HIGH",
        "description": "Slack Webhook URL"
    },
    "discord_webhook": {
        "pattern": r'https://discord(?:app)?\.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9_-]{68}',
        "severity": "HIGH",
        "description": "Discord Webhook URL"
    },
    "github_token": {
        "pattern": r'ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}',
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token"
    },
    "gitlab_token": {
        "pattern": r'glpat-[0-9a-zA-Z_-]{20}',
        "severity": "CRITICAL",
        "description": "GitLab Personal Access Token"
    },
    "private_key": {
        "pattern": r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "severity": "CRITICAL",
        "description": "Private Key Block"
    },

    # ── JSleak-originated patterns (unique additions) ──
    "facebook_access_token": {
        "pattern": r'(?i)(facebook|fb)(.{0,20})?[\'"][0-9]{13,17}[\'"]',
        "severity": "CRITICAL",
        "description": "Facebook Access Token"
    },
    "facebook_oauth": {
        "pattern": r'(?i)facebook(.{0,40})?[\'"][0-9a-f]{32}[\'"]',
        "severity": "CRITICAL",
        "description": "Facebook OAuth Token"
    },
    "facebook_graph": {
        "pattern": r'EAACEdEose0cBA[0-9A-Za-z]+',
        "severity": "CRITICAL",
        "description": "Facebook Graph API Token"
    },
    "google_api_key": {
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "HIGH",
        "description": "Google API Key"
    },
    "google_oauth_id": {
        "pattern": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        "severity": "HIGH",
        "description": "Google OAuth Client ID"
    },
    "google_oauth_token": {
        "pattern": r'ya29\.[0-9A-Za-z\-_]+',
        "severity": "HIGH",
        "description": "Google OAuth Access Token"
    },
    "square_access_token": {
        "pattern": r'sqOatp-[0-9A-Za-z\-_]{22}',
        "severity": "CRITICAL",
        "description": "Square Access Token"
    },
    "square_secret": {
        "pattern": r'sq0csp-[0-9A-Za-z\-_]{43}',
        "severity": "CRITICAL",
        "description": "Square Secret"
    },
    "twilio_key": {
        "pattern": r'SK[0-9a-fA-F]{32}',
        "severity": "CRITICAL",
        "description": "Twilio API Key"
    },
    "twitter_bearer": {
        "pattern": r'(?i)twitter(.{0,20})?[\'"][0-9a-z]{35,44}[\'"]',
        "severity": "HIGH",
        "description": "Twitter Bearer Token"
    },
    "twitter_access_token": {
        "pattern": r'(?i)twitter(.{0,20})?[\'"][0-9a-z]{18,25}[\'"]',
        "severity": "HIGH",
        "description": "Twitter Access Token"
    },
    "mailgun_key": {
        "pattern": r'key-[0-9a-zA-Z]{32}',
        "severity": "HIGH",
        "description": "Mailgun API Key"
    },
    "mailchimp_key": {
        "pattern": r'[0-9a-f]{32}-us[0-9]{1,2}',
        "severity": "HIGH",
        "description": "Mailchimp API Key"
    },
    "heroku_key": {
        "pattern": r'(?i)heroku(.{0,20})?[\'"][0-9a-f]{32}[\'"]',
        "severity": "HIGH",
        "description": "Heroku API Key"
    },
    # NOTE: reCAPTCHA site keys ("6L..." format) removed as a detector.
    # They're meant to be public — embedded client-side by design for the
    # widget to render — and Google doesn't format the private secret key
    # differently enough to distinguish it via regex. Flagging them was a
    # false positive, not a real finding.
    "shopify_token": {
        "pattern": r'shp(at|ca|pa)_[a-fA-F0-9]{32}',
        "severity": "HIGH",
        "description": "Shopify Token"
    },
    "paypal_token": {
        "pattern": r'(?i)paypal(.{0,20})?[\'"][A-Z0-9]{80}[\'"]',
        "severity": "CRITICAL",
        "description": "PayPal Token"
    },
    "npm_auth_token": {
        "pattern": r'(?i)npm[_-]?token[\'"]?\s*[:=]\s*[\'"]?[a-f0-9-]{36}',
        "severity": "HIGH",
        "description": "NPM Auth Token"
    },
    "algolia_key": {
        "pattern": r'(?i)algolia(.{0,20})?[\'"][0-9a-zA-Z]{32}[\'"]',
        "severity": "HIGH",
        "description": "Algolia API Key"
    },
    "mapbox_token": {
        "pattern": r'pk\.[a-zA-Z0-9]{20,}\.[a-zA-Z0-9]{20,}',
        "severity": "HIGH",
        "description": "Mapbox Access Token"
    },
    "spotify_token": {
        "pattern": r'(?i)spotify(.{0,20})?[\'"][0-9a-zA-Z]{32}[\'"]',
        "severity": "HIGH",
        "description": "Spotify Token"
    },
    "generic_secret_assignment": {
        "pattern": r'(?i)\b(secret|password|token|api[_-]?key|client[_-]?secret|private[_-]?key|secret[_-]?key|encryption[_-]?key|encryption[_-]?iv|signing[_-]?key)\s*[:=]\s*[\'"]([^\s\'"]{6,})[\'"]',
        "severity": "HIGH",
        "description": "High-entropy secret assignment"
    },
    "credential_url": {
        "pattern": r'(?i)(?:ftp|ftps|http|https)://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+',
        "severity": "CRITICAL",
        "description": "URL with embedded credentials"
    },

    # ── React/Next/SPA Specific ──
    "react_router_context_leak": {
        "pattern": r'window\.__reactRouterContext\s*=\s*\{[^}]*(?:token|auth|password|secret|key)[^}]*\}',
        "severity": "HIGH",
        "description": "React Router context may contain sensitive data"
    },
    "nextjs_runtime_config": {
        "pattern": r'__NEXT_DATA__\s*=\s*\{.*?"env"\s*:\s*\{([^}]+)\}',
        "severity": "HIGH",
        "description": "Next.js runtime env config exposed"
    },
    "webpack_env_leak": {
        "pattern": r'(?i)(?:REACT_APP_|NEXT_PUBLIC_|VUE_APP_|GATSBY_)[A-Z_]+\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]',
        "severity": "MEDIUM",
        "description": "Environment variable leaked in bundle"
    },
    "graphql_endpoint_with_auth": {
        "pattern": r'(?i)(?:graphql|gql)\s*[:=]\s*[\'"]([^\'"]*graphql[^\'"]*)[\'"].*?[^\n]{0,200}(?:token|auth|key)',
        "severity": "MEDIUM",
        "description": "GraphQL endpoint with nearby auth"
    },
    "postmessage_handler_no_origin": {
        "pattern": r'window\.addEventListener\s*\(\s*[\'"]message[\'"]\s*,\s*(?!.*origin)',
        "severity": "MEDIUM",
        "description": "postMessage handler without origin validation"
    },
    "hardcoded_password": {
        "pattern": r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]{6,})[\'"]',
        "severity": "HIGH",
        "description": "Hardcoded password"
    },
    "s3_bucket_url": {
        "pattern": r'(?i)(?:https?://)[a-z0-9\-\.]*\.s3[\.-][a-z0-9\-]+\.amazonaws\.com[/a-zA-Z0-9\-_\.]*',
        "severity": "LOW",
        "description": "S3 bucket URL"
    },
    "s3_bucket_extended": {
        "pattern": r'(?i)s3[\.\-][a-z0-9-]+\.amazonaws\.com|s3://[a-zA-Z0-9-\._]+|[a-zA-Z0-9-\._]+\.s3[\.\-][a-z0-9-]+\.amazonaws\.com',
        "severity": "LOW",
        "description": "S3 bucket reference"
    },
    "internal_ip": {
        "pattern": r'(?i)(?:https?://)(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9\.]+',
        "severity": "INFO",
        "description": "Internal IP/URL exposed"
    },
    # NOTE: a bare "any x.x.x.x-shaped number sequence" pattern was removed here.
    # It matched version strings, ratios, and decimals (e.g. "1.1.1") indiscriminately —
    # too noisy to be useful. internal_ip above already covers the actionable case
    # (private-range IPs reachable via a URL scheme).
    "email_in_js": {
        "pattern": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "severity": "INFO",
        "description": "Email address in source"
    },
}


# ─────────────────────────────────────────────────────────────
# ROUTE / ENDPOINT EXTRACTION PATTERNS
# ─────────────────────────────────────────────────────────────
# Inspired by jsluice — regex-based extraction of API routes and paths

ROUTE_PATTERNS = {
    "fetch_endpoint": {
        "pattern": r'(?:fetch|axios\.(?:get|post|put|delete|patch|request))\s*\(\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "HTTP client endpoint"
    },
    "xhr_endpoint": {
        "pattern": r'\.open\s*\(\s*[\'"](?:GET|POST|PUT|DELETE|PATCH)[\'"]\s*,\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "XMLHttpRequest endpoint"
    },
    "jquery_ajax": {
        "pattern": r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "jQuery AJAX endpoint"
    },
    "react_router_route": {
        "pattern": r'(?:<Route|path\s*:\s*)[\'"]([^\'"]{2,100})[\'"]',
        "severity": "INFO",
        "description": "React Router path"
    },
    "vue_router_route": {
        "pattern": r'\bpath\s*:\s*[\'"](/[^\'"\s]{1,100})[\'"]',
        "severity": "INFO",
        "description": "Vue Router path"
    },
    "express_route": {
        "pattern": r'(?:app|router)\.(?:get|post|put|delete|patch|use|all)\s*\(\s*[\'"]([^\'"]{2,100})[\'"]',
        "severity": "INFO",
        "description": "Express/Node route"
    },
    "api_path_string": {
        "pattern": r'[\'"]((?:/api/|/v\d+/|/graphql|/rest/|/svc/|/service/|/ws/|/webhook/)[^\'"\s]{2,120})[\'"]',
        "severity": "INFO",
        "description": "API path string"
    },
    "url_constructor": {
        "pattern": r'new\s+URL\s*\(\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "URL constructor call"
    },
    "websocket_endpoint": {
        "pattern": r'new\s+WebSocket\s*\(\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "WebSocket endpoint"
    },
    "event_source": {
        "pattern": r'new\s+EventSource\s*\(\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "SSE/EventSource endpoint"
    },
    "window_location": {
        "pattern": r'(?:window\.)?location\.(?:href|assign|replace)\s*=\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "Location assignment"
    },
    "history_push": {
        "pattern": r'history\.(?:pushState|replaceState)\s*\([^,]+,\s*[^,]+,\s*[\'"]([^\'"]{2,100})[\'"]',
        "severity": "INFO",
        "description": "History API path"
    },
    "import_dynamic": {
        "pattern": r'import\s*\(\s*[\'"]([^\'"]{3,200})[\'"]\s*\)',
        "severity": "INFO",
        "description": "Dynamic import path"
    },
    "static_asset_path": {
        "pattern": r'[\'"]((?:/assets/|/static/|/images/|/fonts/|/media/|/uploads/|/downloads/)[^\'"\s]{2,120})[\'"]',
        "severity": "INFO",
        "description": "Static asset path"
    },
}


# ─────────────────────────────────────────────────────────────
# DIRECTORY / PATH ENUMERATION PATTERNS
# ─────────────────────────────────────────────────────────────
# Extracts directory structures, import trees, and path references

DIRECTORY_PATTERNS = {
    "js_import_path": {
        "pattern": r'(?:import\s+(?:.*?\s+from\s+)?|require\s*\(\s*)[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "JS import/require path"
    },
    "webpack_public_path": {
        "pattern": r'(?:__webpack_require__\.p|publicPath|baseUrl)\s*[:=]\s*[\'"]([^\'"]{3,100})[\'"]',
        "severity": "INFO",
        "description": "Webpack public path"
    },
    "source_map_ref": {
        "pattern": r'//#\s*sourceMappingURL=([^\s\'"]+)',
        "severity": "INFO",
        "description": "Source map reference"
    },
    "template_url": {
        "pattern": r'(?:templateUrl|template)\s*:\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "Template URL/path"
    },
    "config_endpoint": {
        "pattern": r'(?:baseURL|baseUrl|apiUrl|apiURL|endpoint|rootPath)\s*[:=]\s*[\'"]([^\'"]{3,200})[\'"]',
        "severity": "INFO",
        "description": "Config base URL/path"
    },
    "relative_path_string": {
        "pattern": r'[\'"](\.\.?/[a-zA-Z0-9_\-./]{1,120})[\'"]',
        "severity": "INFO",
        "description": "Relative path reference"
    },
    "absolute_path_string": {
        "pattern": r'[\'"](/[a-zA-Z0-9_\-.]+(?:/[a-zA-Z0-9_\-.]+){1,10})[\'"]',
        "severity": "INFO",
        "description": "Absolute path reference"
    },
}


# ─────────────────────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────────────────────

class SPACrawler:
    def __init__(self, target: str, timeout: int = 15, threads: int = 10,
                 headers: Dict[str, str] = None, proxy: str = None,
                 extract_routes: bool = True, extract_dirs: bool = True,
                 min_route_len: int = 2):
        self.target = target.rstrip("/")
        self.domain = urlparse(self.target).netloc
        self.timeout = timeout
        self.threads = threads
        self.extract_routes = extract_routes
        self.extract_dirs = extract_dirs
        self.min_route_len = min_route_len

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.js_files: Set[str] = set()
        self.inline_scripts: List[str] = []
        self.findings: List[Finding] = []
        self.visited: Set[str] = set()
        self.routes: Set[str] = set()
        self.directories: Set[str] = set()

        self.reachable = True
        self.unreachable_reason: str = ""
        self.last_fetch_error: str = ""
        self.summary = ScanSummary(target=self.target)

    # ── Network ──

    def fetch(self, url: str) -> str:
        self.last_fetch_error = ""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp.status_code == 200:
                return resp.text
            self.last_fetch_error = f"HTTP {resp.status_code}"
        except requests.exceptions.SSLError:
            self.last_fetch_error = "SSL error"
        except requests.exceptions.ConnectionError:
            self.last_fetch_error = "connection failed"
        except requests.exceptions.Timeout:
            self.last_fetch_error = "timed out"
        except requests.exceptions.TooManyRedirects:
            self.last_fetch_error = "too many redirects"
        except requests.exceptions.RequestException as e:
            self.last_fetch_error = type(e).__name__
        return ""

    # ── Extraction ──

    def extract_js_from_html(self, html: str, base_url: str) -> Set[str]:
        urls = set()

        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            urls.add(urljoin(base_url, match.group(1)))

        for match in re.finditer(r'<link[^>]+rel=["\']modulepreload["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            urls.add(urljoin(base_url, match.group(1)))

        for match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL):
            script = match.group(1).strip()
            if script and len(script) > 50:
                self.inline_scripts.append(script)

        for match in re.finditer(r'//# sourceMappingURL=([^\s]+)', html):
            urls.add(urljoin(base_url, match.group(1)))

        return urls

    def extract_js_from_js(self, content: str, base_url: str) -> Set[str]:
        urls = set()

        for match in re.finditer(r'import\s*\(["\']([^"\']+)["\']\)', content):
            urls.add(urljoin(base_url, match.group(1)))

        for match in re.finditer(r'(?:__webpack_require__\.p|publicPath|baseUrl)\s*[:=]\s*["\']([^"\']+)["\']', content):
            urls.add(urljoin(base_url, match.group(1)))

        for match in re.finditer(r'["\']((?:/assets/|/static/|/_next/|/chunks/|/js/)[^"\']+\.js)["\']', content):
            urls.add(urljoin(base_url, match.group(1)))

        return urls

    # ── Scanning ──

    def _get_context(self, content: str, start: int, end: int, width: int = 120) -> str:
        ctx_start = max(0, start - width)
        ctx_end = min(len(content), end + width)
        ctx = content[ctx_start:ctx_end].replace("\n", " ").replace("\t", " ")
        return ctx[:240]

    def scan_content(self, content: str, file_url: str) -> List[Finding]:
        findings = []

        # 1. Secret patterns
        for finding_type, config in SECRET_PATTERNS.items():
            for match in re.finditer(config["pattern"], content):
                line_num = content[:match.start()].count("\n") + 1
                match_str = match.group(0)
                if len(match_str) > 80:
                    match_str = match_str[:40] + "..." + match_str[-20:]

                findings.append(Finding(
                    target=self.target,
                    file_url=file_url,
                    finding_type=finding_type,
                    match=match_str,
                    context=self._get_context(content, match.start(), match.end()),
                    severity=config["severity"],
                    line_number=line_num,
                    category="secret"
                ))

        # 2. Route / endpoint extraction
        if self.extract_routes:
            for finding_type, config in ROUTE_PATTERNS.items():
                for match in re.finditer(config["pattern"], content):
                    route = match.group(1) if match.lastindex else match.group(0)
                    if len(route) < self.min_route_len:
                        continue
                    # Deduplicate raw routes
                    self.routes.add(route)
                    line_num = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        target=self.target,
                        file_url=file_url,
                        finding_type=finding_type,
                        match=route,
                        context=self._get_context(content, match.start(), match.end()),
                        severity=config["severity"],
                        line_number=line_num,
                        category="route"
                    ))

        # 3. Directory / path extraction
        if self.extract_dirs:
            for finding_type, config in DIRECTORY_PATTERNS.items():
                for match in re.finditer(config["pattern"], content):
                    path = match.group(1) if match.lastindex else match.group(0)
                    if len(path) < 2:
                        continue
                    self.directories.add(path)
                    line_num = content[:match.start()].count("\n") + 1

                    findings.append(Finding(
                        target=self.target,
                        file_url=file_url,
                        finding_type=finding_type,
                        match=path,
                        context=self._get_context(content, match.start(), match.end()),
                        severity=config["severity"],
                        line_number=line_num,
                        category="directory"
                    ))

        return findings

    # ── Main crawl ──

    def crawl(self, max_depth: int = 2) -> List[Finding]:
        print(f"{C.CYAN}[+]{C.RESET} Starting crawl of {C.BOLD}{self.target}{C.RESET}")

        html = self.fetch(self.target)
        if not html:
            self.reachable = False
            self.unreachable_reason = self.last_fetch_error or "unknown error"
            print(f"{C.RED}[!]{C.RESET} Skipping {self.target} — {self.unreachable_reason}")
            return []

        self.js_files.update(self.extract_js_from_html(html, self.target))

        discovered = set(self.js_files)
        for depth in range(max_depth):
            new_files = set()
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.fetch, url): url for url in discovered}
                for future in as_completed(futures):
                    url = futures[future]
                    content = future.result()
                    if content:
                        self.findings.extend(self.scan_content(content, url))
                        new_files.update(self.extract_js_from_js(content, url))

            discovered = new_files - self.js_files
            if not discovered:
                break
            self.js_files.update(discovered)
            print(f"    {C.DIM}Depth {depth+1}: {len(discovered)} new JS files{C.RESET}")

        # Inline scripts
        if self.inline_scripts:
            print(f"    {C.DIM}Scanning {len(self.inline_scripts)} inline scripts{C.RESET}")
            for i, script in enumerate(self.inline_scripts):
                self.findings.extend(self.scan_content(script, f"{self.target}#inline-{i}"))

        # Deduplicate
        seen = set()
        unique = []
        for f in self.findings:
            key = (f.file_url, f.finding_type, f.match, f.category)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

        # Update summary
        self.summary.js_files_scanned = len(self.js_files)
        self.summary.inline_scripts = len(self.inline_scripts)
        self.summary.secrets_found = sum(1 for f in self.findings if f.category == "secret")
        self.summary.routes_found = len(self.routes)
        self.summary.directories_found = len(self.directories)

        # Print summary
        print(f"{C.GREEN}[+]{C.RESET} Crawl complete. {C.BOLD}{len(self.js_files)}{C.RESET} JS files scanned.")
        print(f"    {C.RED}{self.summary.secrets_found}{C.RESET} secrets | "
              f"{C.YELLOW}{self.summary.routes_found}{C.RESET} routes | "
              f"{C.BLUE}{self.summary.directories_found}{C.RESET} directories")

        return self.findings


# ─────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────

class Reporter:
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEVERITY_COLORS = {
        "CRITICAL": "#ff4444",
        "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",
        "LOW": "#66ccff",
        "INFO": "#999999"
    }
    CONSOLE_SEV = {
        "CRITICAL": C.RED,
        "HIGH": C.YELLOW,
        "MEDIUM": C.YELLOW,
        "LOW": C.BLUE,
        "INFO": C.GREY
    }
    @staticmethod
    def _safe_filename(url: str) -> str:
        return url.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")

    @staticmethod
    def to_json(findings: List[Finding], output_path: str):
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_findings": len(findings),
            "by_category": {},
            "by_severity": {},
            "findings": [asdict(f) for f in findings]
        }
        for f in findings:
            data["by_category"][f.category] = data["by_category"].get(f.category, 0) + 1
            data["by_severity"][f.severity] = data["by_severity"].get(f.severity, 0) + 1

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{C.GREEN}[+]{C.RESET} JSON report: {output_path}")

    @staticmethod
    def to_html(findings: List[Finding], output_path: str, target: str, summary: ScanSummary = None):
        # Group by category then severity
        cats = defaultdict(lambda: defaultdict(list))
        for f in findings:
            cats[f.category][f.severity].append(f)

        def render_table(cat_findings: List[Finding]) -> str:
            rows = ""
            for f in cat_findings:
                color = Reporter.SEVERITY_COLORS.get(f.severity, "#999")
                match_display = f.match.replace("<", "&lt;").replace(">", "&gt;")
                ctx = f.context.replace("<", "&lt;").replace(">", "&gt;")[:180]
                file_link = f.file_url if f.file_url.startswith("http") else "#"
                rows += f"""<tr>
                    <td><span class="badge" style="background:{color}">{f.severity}</span></td>
                    <td><code>{f.finding_type}</code></td>
                    <td><code class="match">{match_display}</code></td>
                    <td class="ctx">{ctx}...</td>
                    <td><a href="{file_link}" target="_blank">{f.file_url[:70]}</a></td>
                    <td>{f.line_number}</td>
                </tr>"""
            return rows

        sections = ""
        for cat in ["secret", "route", "directory", "cloud"]:
            if cat not in cats:
                continue
            sections += f"<h2>{cat.title()}s</h2>"
            for sev in Reporter.SEVERITY_ORDER:
                if sev not in cats[cat]:
                    continue
                items = cats[cat][sev]
                sections += f"<h3>{sev} <span class='count'>({len(items)})</span></h3>"
                sections += f"""<table>
                    <tr><th>Severity</th><th>Type</th><th>Match</th><th>Context</th><th>Source</th><th>Line</th></tr>
                    {render_table(items)}
                </table>"""

        summary_html = ""
        if summary:
            summary_html = f"""
            <div class="summary">
                <div class="card"><h4>JS Files</h4><p>{summary.js_files_scanned}</p></div>
                <div class="card"><h4>Secrets</h4><p class="c">{summary.secrets_found}</p></div>
                <div class="card"><h4>Routes</h4><p class="y">{summary.routes_found}</p></div>
                <div class="card"><h4>Directories</h4><p class="b">{summary.directories_found}</p></div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>SPAFox Report — {target}</title>
<style>
:root{{--bg:#0d1117;--fg:#c9d1d9;--accent:#58a6ff;--card:#161b22;--border:#30363d}}
body{{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:2rem;background:var(--bg);color:var(--fg);line-height:1.5}}
header{{border-bottom:1px solid var(--border);padding-bottom:1rem;margin-bottom:1.5rem}}
h1{{color:var(--accent);margin:0}} h2{{color:#f0883e;margin-top:2rem}} h3{{color:#d29922;font-size:1rem;margin-top:1.5rem}}
.meta{{color:#8b949e;font-size:0.9rem}}
table{{width:100%;border-collapse:collapse;margin:0.5rem 0 1.5rem;font-size:0.9rem}}
th,td{{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}}
th{{background:var(--card);color:#f0f6fc;font-weight:600;position:sticky;top:0}}
tr:hover{{background:var(--card)}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;font-family:ui-monospace,SFMono-Regular,monospace;font-size:0.85em;word-break:break-all}}
code.match{{background:transparent;padding:0;color:#ff7b72}}
.ctx{{color:#8b949e;font-size:0.85em;max-width:400px}}
a{{color:var(--accent);text-decoration:none}} a:hover{{text-decoration:underline}}
.badge{{padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:bold;color:#fff}}
.summary{{display:flex;gap:1rem;margin:1rem 0;flex-wrap:wrap}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;min-width:120px;text-align:center}}
.card h4{{margin:0 0 0.5rem;color:#8b949e;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.05em}}
.card p{{margin:0;font-size:1.5rem;font-weight:bold;color:var(--fg)}}
.card p.c{{color:#ff7b72}} .card p.y{{color:#d29922}} .card p.b{{color:#58a6ff}}
.count{{color:#8b949e;font-weight:normal}}
</style></head>
<body>
<header>
<h1>SPAFox Report</h1>
<p class="meta">Target: <b>{target}</b> | Generated: {datetime.now().isoformat()} | Total: {len(findings)} findings</p>
{summary_html}
</header>
{sections}
</body></html>"""

        with open(output_path, "w") as f:
            f.write(html)
        print(f"{C.GREEN}[+]{C.RESET} HTML report: {output_path}")

    @staticmethod
    def to_console(findings: List[Finding], summary: ScanSummary = None):
        if not findings:
            print(f"{C.GREEN}[+]{C.RESET} No findings.")
            return

        # Group by category then severity
        cats = defaultdict(lambda: defaultdict(list))
        for f in findings:
            cats[f.category][f.severity].append(f)

        for cat in ["secret", "route", "directory", "cloud"]:
            if cat not in cats:
                continue
            print(f"\n{C.BOLD}{cat.upper()}S{C.RESET}")
            print("─" * 70)
            for sev in Reporter.SEVERITY_ORDER:
                if sev not in cats[cat]:
                    continue
                sev_color = Reporter.CONSOLE_SEV.get(sev, C.RESET)
                items = cats[cat][sev]
                print(f"\n  {sev_color}{sev}{C.RESET} ({len(items)})")
                for f in items:
                    match_display = f.match[:70] + "..." if len(f.match) > 70 else f.match
                    print(f"    {C.DIM}[{f.finding_type}]{C.RESET} {match_display}")
                    print(f"    {C.DIM}    → {f.file_url}:{f.line_number}{C.RESET}")

        if summary:
            print(f"\n{'─' * 70}")
            print(f"  {C.BOLD}Summary:{C.RESET} {summary.js_files_scanned} JS files | "
                  f"{C.RED}{summary.secrets_found}{C.RESET} secrets | "
                  f"{C.YELLOW}{summary.routes_found}{C.RESET} routes | "
                  f"{C.BLUE}{summary.directories_found}{C.RESET} directories")


# ─────────────────────────────────────────────────────────────
# BATCH MODE
# ─────────────────────────────────────────────────────────────

def batch_scan(targets_file: str, output_dir: str, threads: int = 10,
               js_depth: int = 2, proxy: str = None,
               extract_routes: bool = True, extract_dirs: bool = True):
    with open(targets_file) as f:
        targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"{C.CYAN}[+]{C.RESET} Batch mode: {C.BOLD}{len(targets)}{C.RESET} targets")
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    all_findings = []
    unreachable = []
    scanned = 0

    for i, target in enumerate(targets, 1):
        print(f"\n{C.CYAN}[{i}/{len(targets)}]{C.RESET} {target}")
        try:
            crawler = SPACrawler(target, threads=threads, proxy=proxy,
                                 extract_routes=extract_routes, extract_dirs=extract_dirs)
            findings = crawler.crawl(max_depth=js_depth)

            if not crawler.reachable:
                unreachable.append((target, crawler.unreachable_reason))
                continue

            safe_name = Reporter._safe_filename(target)
            Reporter.to_json(findings, f"{output_dir}/{safe_name}.json")
            Reporter.to_html(findings, f"{output_dir}/{safe_name}.html", target, crawler.summary)

            all_findings.extend(findings)
            scanned += 1
        except Exception as e:
            print(f"{C.RED}[!]{C.RESET} Failed on {target}: {e}")
            unreachable.append((target, str(e)))

    # Master reports
    Reporter.to_json(all_findings, f"{output_dir}/MASTER_REPORT.json")
    Reporter.to_html(all_findings, f"{output_dir}/MASTER_REPORT.html", "BATCH SCAN")
    Reporter.to_console(all_findings)

    if unreachable:
        unreachable_path = f"{output_dir}/unreachable_targets.txt"
        with open(unreachable_path, "w") as f:
            for target, reason in unreachable:
                f.write(f"{target}\t{reason}\n")
        print(f"\n{C.YELLOW}[!]{C.RESET} {len(unreachable)} unreachable — see {unreachable_path}")

    print(f"\n{C.GREEN}[+]{C.RESET} Batch complete. {scanned}/{len(targets)} scanned. {len(all_findings)} total findings.")
    print(f"{C.GREEN}[+]{C.RESET} Reports: {output_dir}/")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SPAFox v3.0 — React/Next.js Secret Hunter + Route Intel",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target (default: secrets + routes + dirs)
  python3 spafox.py -u https://example.com/

  # Secrets only
  python3 spafox.py -u https://example.com/ --no-routes --no-dirs

  # Batch scan 600+ apps
  python3 spafox.py -f targets.txt -o reports/ --threads 20

  # Deep crawl with proxy
  python3 spafox.py -u https://example.com -d 3 --proxy http://127.0.0.1:8080
        """
    )
    parser.add_argument("-u", "--url", help="Single target URL")
    parser.add_argument("-f", "--file", help="File with target URLs (one per line)")
    parser.add_argument("-o", "--output", default="spafox_output", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("-d", "--depth", type=int, default=2, help="JS chunk crawl depth")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--headers", help="Custom headers as JSON string")
    parser.add_argument("--no-routes", action="store_true", help="Disable route/endpoint extraction")
    parser.add_argument("--no-dirs", action="store_true", help="Disable directory/path extraction")
    parser.add_argument("--min-route-len", type=int, default=2, help="Minimum route length to report")

    args = parser.parse_args()

    print_banner()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    headers = json.loads(args.headers) if args.headers else None
    extract_routes = not args.no_routes
    extract_dirs = not args.no_dirs

    if args.file:
        batch_scan(args.file, args.output, args.threads, args.depth, args.proxy,
                   extract_routes, extract_dirs)
    else:
        crawler = SPACrawler(args.url, threads=args.threads, proxy=args.proxy,
                             headers=headers, extract_routes=extract_routes,
                             extract_dirs=extract_dirs, min_route_len=args.min_route_len)
        findings = crawler.crawl(max_depth=args.depth)

        Path(args.output).mkdir(parents=True, exist_ok=True)
        safe_name = Reporter._safe_filename(args.url)
        Reporter.to_json(findings, f"{args.output}/{safe_name}.json")
        Reporter.to_html(findings, f"{args.output}/{safe_name}.html", args.url, crawler.summary)
        Reporter.to_console(findings, crawler.summary)


if __name__ == "__main__":
    main()