#!/usr/bin/env python3
"""
detect_db.py — Ermittelt, welche Datenbank / welches Backend die Webseite
app.recruiting.ki verwendet.

Die Seite ist eine Single-Page-App (Vite/React). Welche Datenbank im Hintergrund
laeuft, laesst sich von aussen nur indirekt feststellen: ueber das ausgelieferte
JavaScript-Bundle, die darin enthaltenen API-URLs und die HTTP-Signaturen der
Backend-Endpunkte.

Das Skript:
  1. laedt die Startseite und findet das JS-Bundle,
  2. durchsucht das Bundle nach Backend-/Datenbank-Signaturen,
  3. extrahiert die konkrete Supabase-Projekt-URL,
  4. prueft die Backend-Endpunkte live (REST / Auth-Health),
  5. gibt einen kurzen Bericht aus.

Nur Standardbibliothek -> laeuft ohne `pip install`.
"""

from __future__ import annotations

import re
import sys
import json
import urllib.request
import urllib.error
from collections import Counter
from urllib.parse import urljoin

BASE_URL = "https://app.recruiting.ki"
TIMEOUT = 30
UA = "Mozilla/5.0 (db-detector; +https://app.recruiting.ki)"

# Signaturen, nach denen wir im Bundle suchen, gruppiert nach Technologie.
SIGNATURES = {
    "Supabase (PostgreSQL)": r"supabase",
    "PostgreSQL / PostgREST": r"postgrest|postgres",
    "Firebase / Firestore": r"firebaseio|firestore|firebaseapp",
    "MongoDB": r"mongodb|mongo(?![a-z])",
    "MySQL": r"mysql",
    "DynamoDB": r"dynamodb",
    "GraphQL / Hasura": r"hasura|graphql",
    "Redis": r"redis",
}


def fetch(url: str, binary: bool = False):
    """Laedt eine URL und gibt (text, headers) zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read()
        headers = dict(resp.headers)
        if binary:
            return raw, headers
        return raw.decode("utf-8", errors="replace"), headers


def find_bundles(html: str) -> list[str]:
    """Findet die <script src=...>-JS-Bundles in der HTML-Seite."""
    srcs = re.findall(r'src="([^"]+\.js)"', html)
    return [urljoin(BASE_URL + "/", s) for s in srcs]


def scan_signatures(js: str) -> Counter:
    counts = Counter()
    for label, pattern in SIGNATURES.items():
        n = len(re.findall(pattern, js, flags=re.IGNORECASE))
        if n:
            counts[label] = n
    return counts


def find_supabase_project(js: str) -> str | None:
    m = re.search(r"https://([a-z0-9]{15,})\.supabase\.(?:co|in)", js)
    return m.group(0) if m else None


def find_endpoints(js: str) -> list[str]:
    eps = set(re.findall(r"/functions/v1/[a-zA-Z0-9._-]+", js))
    return sorted(eps)


def probe(url: str) -> str:
    """Prueft einen Endpunkt live und gibt eine kurze Statuszeile zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return f"HTTP {resp.status}  server={resp.headers.get('server','?')}"
    except urllib.error.HTTPError as e:
        body = e.read(200).decode("utf-8", errors="replace").replace("\n", " ")
        return f"HTTP {e.code}  server={e.headers.get('server','?')}  body={body!r}"
    except Exception as e:  # noqa: BLE001
        return f"FEHLER: {e}"


def main() -> int:
    print(f"[*] Lade Startseite: {BASE_URL}")
    html, _ = fetch(BASE_URL)

    bundles = find_bundles(html)
    if not bundles:
        print("[!] Kein JS-Bundle gefunden — Seite evtl. geaendert.")
        return 1
    print(f"[*] JS-Bundle(s): {', '.join(bundles)}")

    js, _ = fetch(bundles[0])
    print(f"[*] Bundle-Groesse: {len(js):,} Zeichen\n")

    counts = scan_signatures(js)
    print("=== Gefundene Backend-/DB-Signaturen (Treffer im Bundle) ===")
    for label, n in counts.most_common():
        print(f"  {n:>4}x  {label}")

    project = find_supabase_project(js)
    print("\n=== Backend-Projekt ===")
    if project:
        print(f"  Supabase-Projekt-URL: {project}")
    else:
        print("  Keine Supabase-Projekt-URL gefunden.")

    endpoints = find_endpoints(js)
    if endpoints:
        print(f"\n=== Supabase Edge Functions ({len(endpoints)} gefunden) ===")
        for ep in endpoints[:25]:
            print(f"  {ep}")
        if len(endpoints) > 25:
            print(f"  ... (+{len(endpoints) - 25} weitere)")

    if project:
        print("\n=== Live-Pruefung der Backend-Endpunkte ===")
        print(f"  REST  /rest/v1/        -> {probe(project + '/rest/v1/')}")
        print(f"  Auth  /auth/v1/health  -> {probe(project + '/auth/v1/health')}")

    # Fazit
    print("\n=== FAZIT ===")
    if counts and "Supabase" in counts.most_common()[0][0]:
        print("  Datenbank: PostgreSQL — bereitgestellt ueber Supabase (BaaS).")
        print("  Datenzugriff: PostgREST (/rest/v1), Auth (/auth/v1),")
        print("  Serverlogik ueber Supabase Edge Functions (Deno, /functions/v1).")
    else:
        print("  Kein eindeutiges Supabase-Signal — siehe Trefferliste oben.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
