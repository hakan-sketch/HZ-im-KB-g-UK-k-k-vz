#!/usr/bin/env python3
"""
detect_backend.py — Ermittelt fuer eine oder mehrere Webseiten (inkl. Subdomains),
welches Hosting/Backend und welche Datenbank verwendet wird.

Methode (nur von aussen, ohne Login):
  * HTTP-Header / Server-Signatur (Cloudflare, Squarespace, nginx, Vercel, Netlify ...)
  * JS-Bundles laden und nach Backend-/DB-Signaturen durchsuchen
    (Supabase, Firebase, MongoDB, GraphQL/Hasura, ...)
  * konkrete Backend-URLs (z. B. *.supabase.co) extrahieren

Optionale Subdomain-Erkennung ueber Certificate Transparency (crt.sh).

Aufruf:
    python3 detect_backend.py recruit-ai.co therecruit.ai hr-on.com
    python3 detect_backend.py --subdomains recruit-ai.co
    python3 detect_backend.py https://app.recruiting.ki

Nur Standardbibliothek -> kein pip noetig.
"""

from __future__ import annotations

import re
import sys
import json
import argparse
import urllib.request
import urllib.error
from collections import Counter
from urllib.parse import urljoin, urlparse

TIMEOUT = 30
UA = "Mozilla/5.0 (backend-detector)"

# Server-/Hosting-Signaturen aus HTTP-Headern.
SERVER_HINTS = {
    "cloudflare": "Cloudflare (CDN/Proxy)",
    "netlify": "Netlify (Static/JAMstack Hosting)",
    "vercel": "Vercel (Hosting)",
    "squarespace": "Squarespace (Website-Baukasten)",
    "nginx": "nginx (eigener/VPS-Server)",
    "apache": "Apache (eigener/VPS-Server)",
    "gws": "Google Web Server",
    "amazons3": "AWS S3 (Static Hosting)",
    "github.com": "GitHub Pages",
    "wix": "Wix",
    "shopify": "Shopify",
}

# Backend-/DB-Signaturen im JS-Bundle.
DB_SIGNATURES = {
    "Supabase (PostgreSQL)": r"supabase",
    "PostgreSQL / PostgREST": r"postgrest|postgres",
    "Firebase / Firestore": r"firebaseio|firestore|firebaseapp",
    "MongoDB": r"mongodb|mongo(?![a-z])",
    "MySQL": r"mysql",
    "DynamoDB": r"dynamodb",
    "GraphQL / Hasura": r"hasura|graphql",
    "Redis": r"redis",
    "Airtable": r"airtable",
    "Sanity CMS": r"sanity\.io|apicdn\.sanity",
    "Contentful": r"contentful",
    "WordPress": r"wp-content|wp-json|wordpress",
}

BACKEND_URL_PATTERNS = [
    r"https://[a-z0-9]{15,}\.supabase\.(?:co|in)",
    r"https://[a-z0-9-]+\.firebaseio\.com",
    r"https://[a-z0-9-]+\.firebaseapp\.com",
    r"https://[a-z0-9-]+\.herokuapp\.com",
    r"https://[a-z0-9-]+\.amazonaws\.com",
    r"https://[a-z0-9-]+\.hasura\.app",
]


def fetch(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read().decode("utf-8", "replace"), dict(resp.headers), resp.geturl()


def head(url: str):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, dict(resp.headers), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), url
    except Exception as e:  # noqa: BLE001
        return None, {"_error": str(e)}, url


def server_label(headers: dict) -> str:
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    found = [label for key, label in SERVER_HINTS.items() if key in blob]
    return ", ".join(dict.fromkeys(found)) or headers.get("server", "unbekannt")


def crt_subdomains(domain: str) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for _ in range(3):
        try:
            txt, _, _ = fetch(url)
            data = json.loads(txt)
            names: set[str] = set()
            for row in data:
                names.update(row.get("name_value", "").split("\n"))
            return sorted(n.strip() for n in names if "*" not in n and n.strip())
        except Exception:
            continue
    return []


def analyze(target: str) -> None:
    if not target.startswith("http"):
        target = "https://" + target
    host = urlparse(target).netloc
    print(f"\n{'='*70}\n  {host}\n{'='*70}")

    status, headers, final = head(target)
    if status is None:
        print(f"  NICHT ERREICHBAR: {headers.get('_error')}")
        return
    print(f"  HTTP {status}  ->  {final}")
    print(f"  Hosting/Server: {server_label(headers)}")
    if "x-powered-by" in {k.lower() for k in headers}:
        xp = next(v for k, v in headers.items() if k.lower() == "x-powered-by")
        print(f"  X-Powered-By: {xp}")

    # HTML + Bundles holen
    try:
        html, _, _ = fetch(target)
    except Exception as e:  # noqa: BLE001
        print(f"  HTML konnte nicht geladen werden: {e}")
        return

    generator = re.search(r'<meta name="generator" content="([^"]+)"', html, re.I)
    if generator:
        print(f"  Generator-Meta: {generator.group(1)}")

    bundles = [urljoin(final, s) for s in re.findall(r'src="([^"]+\.js)"', html)]
    big_js = ""
    for b in bundles[:6]:
        try:
            js, _, _ = fetch(b)
            big_js += js
        except Exception:
            pass

    haystack = html + big_js
    counts = Counter()
    for label, pat in DB_SIGNATURES.items():
        n = len(re.findall(pat, haystack, re.I))
        if n:
            counts[label] = n

    if counts:
        print("  DB-/Backend-Signaturen:")
        for label, n in counts.most_common():
            print(f"      {n:>4}x  {label}")
    else:
        print("  Keine DB-/Backend-Signaturen im Frontend gefunden "
              "(reine Static-/CMS-Seite oder Backend gut versteckt).")

    backend_urls: set[str] = set()
    for pat in BACKEND_URL_PATTERNS:
        backend_urls.update(re.findall(pat, haystack, re.I))
    if backend_urls:
        print("  Backend-URLs:")
        for u in sorted(backend_urls):
            print(f"      {u}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Backend/DB-Detektor")
    ap.add_argument("targets", nargs="+", help="Domains oder URLs")
    ap.add_argument("--subdomains", action="store_true",
                    help="Subdomains via crt.sh ermitteln und mitanalysieren")
    args = ap.parse_args()

    targets: list[str] = []
    for t in args.targets:
        targets.append(t)
        if args.subdomains:
            dom = urlparse(t if t.startswith("http") else "https://" + t).netloc
            subs = crt_subdomains(dom)
            print(f"[crt.sh] {dom}: {len(subs)} Hostname(n) gefunden")
            targets.extend(s for s in subs if s != dom)

    seen = set()
    for t in targets:
        host = urlparse(t if t.startswith("http") else "https://" + t).netloc
        if host in seen:
            continue
        seen.add(host)
        analyze(t)
    return 0


if __name__ == "__main__":
    sys.exit(main())
