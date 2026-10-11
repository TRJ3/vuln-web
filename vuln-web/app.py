#!/usr/bin/env python3
"""
vuln-web - Ein absichtlich verwundbares Mini-Webziel fuer einen CTF-Probelauf.

Zweck: lokales Testziel, um eine Pruef-/Audit-Kette einmal durchzuspielen.
Es enthaelt drei klar unterscheidbare, klassische Schwachstellen. Jede gibt bei
erfolgreicher Ausnutzung eine eindeutige Flag-Markerzeichenkette zurueck, damit
ein Testlauf automatisch pruefbar ist.

WARNUNG: Dieser Code ist mit Absicht unsicher. Nur lokal (127.0.0.1) betreiben,
niemals ins Netz stellen und nicht als Vorlage fuer echten Code verwenden.

Start:   python app.py            (Standardport 8000)
         python app.py 8080       (eigener Port)
Stop:    Strg+C
"""

from __future__ import annotations

import base64
import html
import http.cookies
import json
import os
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --------------------------------------------------------------------------
# Konfiguration
# --------------------------------------------------------------------------

HOST = "127.0.0.1"               # bewusst nur lokal gebunden
DEFAULT_PORT = 8000
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln-web.db")

# Die drei Flags. Sie werden in die SQLite-Datei geschrieben und nur auf dem
# jeweiligen Ausnutzungspfad an den Client ausgeliefert.
FLAG_SQLI = "FLAG{sqli-login-bypass-7Qk2pL}"
FLAG_BAC = "FLAG{broken-access-admin-9Lm5xR}"
FLAG_XSS = "FLAG{reflected-xss-3Zt8wN}"

# Nur fuer den Extraktions-Testlauf: EIN zusaetzlicher Flag, der absichtlich an
# "versteckten" Stellen ausgeliefert wird (Header, Cookie, base64, nested JSON).
# Er liegt in einer EIGENEN secrets-Zeile ('variant') — also in einer anderen
# "Spalte"/Quelle als die drei bekannten Flags. Die drei klassischen Luecken und
# ihre Ausnutzungspfade bleiben davon voellig unberuehrt (Happy Path = gruen).
FLAG_VARIANT = "FLAG{hidden-variant-Qw9zY4}"


# --------------------------------------------------------------------------
# Datenbank
# --------------------------------------------------------------------------

def init_db() -> None:
    """Legt die SQLite-Datei an und befuellt sie, falls noch nicht vorhanden."""
    fresh = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    try:
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        if fresh:
            cur.executemany(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                [
                    ("alice", "s3cret-alice", "user"),
                    ("bob", "hunter2", "user"),
                    ("admin", "do-not-use-this-in-prod", "admin"),
                ],
            )
            cur.executemany(
                "INSERT INTO products (name, description) VALUES (?, ?)",
                [
                    ("Kaffee", "Dunkle Roestung, 1kg"),
                    ("Tee", "Gruener Tee, lose"),
                    ("Keks", "Hafer, Packung mit 12"),
                ],
            )
            cur.executemany(
                "INSERT INTO secrets (key, value) VALUES (?, ?)",
                [
                    ("sqli", FLAG_SQLI),
                    ("bac", FLAG_BAC),
                    ("xss", FLAG_XSS),
                ],
            )
        # Varianten-Flag idempotent sicherstellen (auch in bereits bestehenden
        # DB-Dateien): eigene secrets-Zeile, stoert die drei bekannten nicht.
        cur.execute(
            "INSERT OR IGNORE INTO secrets (key, value) VALUES ('variant', ?)",
            (FLAG_VARIANT,),
        )
        conn.commit()
    finally:
        conn.close()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------------------------------
# HTML-Hilfen
# --------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>vuln-web</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 48rem; margin: 2rem auto;">
{body}
</body>
</html>"""


def page(body: str) -> bytes:
    return PAGE.format(body=body).encode("utf-8")


NAV = """
<h1>vuln-web (Testziel)</h1>
<p>Absichtlich verwundbar. Nur zum lokalen Ueben.</p>
<ul>
  <li><a href="/">Start</a></li>
  <li><a href="/search?q=Kaffee">Produktsuche</a></li>
  <li><a href="/hello?name=Welt">Begruessung</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/admin">Admin</a></li>
  <li><a href="/variant">Flag-Varianten (Test)</a></li>
</ul>
<hr>
"""


# --------------------------------------------------------------------------
# Request-Handler
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "vuln-web/1.0"

    # -- kleine Helfer ----------------------------------------------------

    def send_html(self, body: str, status: int = 200) -> None:
        payload = page(NAV + body)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_raw(self, payload: bytes, *, status: int = 200,
                 content_type: str = "text/html; charset=utf-8",
                 extra_headers: list[tuple[str, str]] | None = None) -> None:
        """Rohantwort mit frei waehlbarem Content-Type und Zusatz-Headern (fuer die
        Flag-Varianten: Flag im Header/Cookie bzw. JSON-Body)."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra_headers or []):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        parsed = parse_qs(raw, keep_blank_values=True)
        return {k: v[0] for k, v in parsed.items()}

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- Routing ----------------------------------------------------------

    def do_GET(self) -> None:
        route = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(route.query).items()}

        if route.path == "/":
            self.route_home()
        elif route.path == "/search":
            self.route_search(params.get("q", ""))
        elif route.path == "/hello":
            self.route_hello(params.get("name", "Welt"))
        elif route.path == "/login":
            self.route_login_form()
        elif route.path == "/admin":
            self.route_admin()
        elif route.path == "/variant":
            self.route_variant(params)
        else:
            self.send_html("<p>Nicht gefunden.</p>", status=404)

    def do_POST(self) -> None:
        route = urlparse(self.path)
        if route.path == "/login":
            self.route_login_submit(self.read_form())
        else:
            self.send_html("<p>Nicht gefunden.</p>", status=404)

    # -- Seiten -----------------------------------------------------------

    def route_home(self) -> None:
        self.send_html(
            "<h2>Start</h2>"
            "<p>Waehle oben eine Funktion. Dies ist ein Uebungsziel.</p>"
        )

    def route_search(self, q: str) -> None:
        """Produktsuche - korrekt parametrisiert (zum Kontrast, keine Luecke)."""
        rows = []
        if q:
            conn = db()
            try:
                cur = conn.execute(
                    "SELECT name, description FROM products WHERE name LIKE ?",
                    (f"%{q}%",),
                )
                rows = cur.fetchall()
            finally:
                conn.close()
        items = "".join(
            f"<li><b>{html.escape(r['name'])}</b>: {html.escape(r['description'])}</li>"
            for r in rows
        )
        body = (
            "<h2>Produktsuche</h2>"
            '<form method="get" action="/search">'
            f'<input name="q" value="{html.escape(q)}" placeholder="Suchbegriff">'
            '<button>Suchen</button></form>'
            f"<ul>{items or '<li>keine Treffer</li>'}</ul>"
        )
        self.send_html(body)

    def route_hello(self, name: str) -> None:
        """Begruessung - gibt die Eingabe ungeprueft zurueck (Reflected XSS)."""
        # Die Eingabe wird ohne Escaping in die Antwort geschrieben.
        greeting = f"<p>Hallo, {name}!</p>"

        extra = ""
        # Enthaelt die Eingabe aktives Markup, gilt die Injektion als gelungen:
        # dann wird die XSS-Flag mit ausgeliefert (macht den Testlauf pruefbar).
        if "<" in name:
            conn = db()
            try:
                flag = conn.execute(
                    "SELECT value FROM secrets WHERE key = 'xss'"
                ).fetchone()["value"]
            finally:
                conn.close()
            extra = f"<!-- {flag} -->"

        body = (
            "<h2>Begruessung</h2>"
            '<form method="get" action="/hello">'
            '<input name="name" placeholder="Dein Name">'
            '<button>Gruessen</button></form>'
            f"{greeting}{extra}"
        )
        self.send_html(body)

    def route_login_form(self) -> None:
        body = (
            "<h2>Login</h2>"
            '<form method="post" action="/login">'
            '<p><input name="username" placeholder="Benutzername"></p>'
            '<p><input name="password" type="password" placeholder="Passwort"></p>'
            "<button>Anmelden</button></form>"
        )
        self.send_html(body)

    def route_login_submit(self, form: dict[str, str]) -> None:
        """Login - Abfrage per String-Verkettung gebaut (SQL-Injection)."""
        username = form.get("username", "")
        password = form.get("password", "")

        # Benutzereingaben werden direkt in die SQL-Abfrage eingesetzt.
        query = (
            "SELECT username, role FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )

        conn = db()
        try:
            try:
                row = conn.execute(query).fetchone()
            except sqlite3.Error as exc:
                self.send_html(f"<h2>Login</h2><p>DB-Fehler: {html.escape(str(exc))}</p>")
                return

            if not row:
                self.send_html("<h2>Login</h2><p>Falsche Zugangsdaten.</p>", status=401)
                return

            role = row["role"]
            if role == "admin":
                flag = conn.execute(
                    "SELECT value FROM secrets WHERE key = 'sqli'"
                ).fetchone()["value"]
                body = (
                    f"<h2>Willkommen, {html.escape(row['username'])}</h2>"
                    "<p>Du bist als <b>admin</b> angemeldet.</p>"
                    f"<p>SQLi-Flag: <code>{html.escape(flag)}</code></p>"
                )
            else:
                body = (
                    f"<h2>Willkommen, {html.escape(row['username'])}</h2>"
                    f"<p>Rolle: {html.escape(role)}</p>"
                )
            self.send_html(body)
        finally:
            conn.close()

    def route_admin(self) -> None:
        """Admin-Panel - prueft die Rolle nicht (Broken Access Control)."""
        # Eine Session-Cookie wird gelesen, aber nie erzwungen: jeder Aufruf
        # bekommt das Admin-Panel samt Flag.
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        who = cookie["session"].value if "session" in cookie else "anonym"

        conn = db()
        try:
            flag = conn.execute(
                "SELECT value FROM secrets WHERE key = 'bac'"
            ).fetchone()["value"]
        finally:
            conn.close()

        body = (
            "<h2>Admin-Panel</h2>"
            f"<p>Sitzung: {html.escape(who)}</p>"
            "<p>Interner Bereich - eigentlich nur fuer Admins.</p>"
            f"<p>Access-Control-Flag: <code>{html.escape(flag)}</code></p>"
        )
        self.send_html(body)

    def route_variant(self, params: dict[str, str]) -> None:
        """NUR fuer den Extraktions-Testlauf: liefert FLAG_VARIANT an bewusst
        "versteckten" Stellen aus (Header, Cookie, base64, nested JSON), steuerbar
        ueber ``?kind=``. Der Flag kommt aus einer EIGENEN secrets-Zeile
        ('variant') — die drei klassischen Luecken und ihre Pfade bleiben
        unberuehrt. Fuer header/cookie/base64 taucht der KLARTEXT-Flag bewusst NICHT
        im Body auf, damit der Testlauf wirklich die versteckte Stelle prueft."""
        conn = db()
        try:
            flag = conn.execute(
                "SELECT value FROM secrets WHERE key = 'variant'"
            ).fetchone()["value"]
        finally:
            conn.close()

        kind = params.get("kind", "")

        if kind == "header":
            body = page(NAV +
                        "<h2>Variante: Header</h2>"
                        "<p>Der Flag steckt NICHT im Body, sondern im Response-Header "
                        "<code>X-CTF-Flag</code>.</p>")
            self.send_raw(body, extra_headers=[("X-CTF-Flag", flag)])
            return

        if kind == "cookie":
            body = page(NAV +
                        "<h2>Variante: Cookie</h2>"
                        "<p>Der Flag steckt in einem <code>Set-Cookie</code>-Header.</p>")
            self.send_raw(body, extra_headers=[("Set-Cookie", f"ctf_flag={flag}; Path=/")])
            return

        if kind == "base64":
            enc = base64.b64encode(flag.encode()).decode()
            body = page(NAV +
                        "<h2>Variante: base64</h2>"
                        "<p>Der Flag ist base64-kodiert und steht als Kommentar im "
                        f"Quelltext.</p><!-- {enc} -->")
            self.send_raw(body)
            return

        if kind == "json":
            payload = {
                "ok": True,
                "data": {
                    "items": [{"id": 1, "name": "Kaffee"}, {"id": 2, "name": "Tee"}],
                    "meta": {"issued_by": "vuln-web", "token": flag},
                },
            }
            self.send_raw(json.dumps(payload).encode("utf-8"),
                          content_type="application/json; charset=utf-8")
            return

        if kind == "b64json":
            enc = base64.b64encode(flag.encode()).decode()
            payload = {"ok": True, "data": {"blob": enc, "encoding": "base64"}}
            self.send_raw(json.dumps(payload).encode("utf-8"),
                          content_type="application/json; charset=utf-8")
            return

        # Index (ohne Flag im Body): verfuegbare Varianten auflisten.
        rows = [
            ("header", "Flag im Response-Header X-CTF-Flag"),
            ("cookie", "Flag im Set-Cookie-Header"),
            ("base64", "Flag base64-kodiert im Body-Kommentar"),
            ("json", "Flag als Klartext nested im JSON"),
            ("b64json", "Flag base64-kodiert nested im JSON"),
        ]
        links = "".join(
            f'<li><a href="/variant?kind={k}">{k}</a> &ndash; {desc}</li>'
            for k, desc in rows
        )
        self.send_html(
            "<h2>Flag-Varianten (nur Test)</h2>"
            "<p>Derselbe Flag an bewusst versteckten Stellen &ndash; zum Pruefen der "
            f"zentralen Extraktion.</p><ul>{links}</ul>"
        )


# --------------------------------------------------------------------------
# Start
# --------------------------------------------------------------------------

def main() -> None:
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        port = int(sys.argv[1])

    init_db()
    server = ThreadingHTTPServer((HOST, port), Handler)
    print(f"vuln-web laeuft auf http://{HOST}:{port}  (Strg+C zum Beenden)")
    print(f"SQLite-Datei: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nBeende ...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
