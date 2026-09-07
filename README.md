# MikroTik/RouterOS Fleet Security Scanner

Fleet-level vulnerability and misconfiguration visibility for MikroTik/RouterOS
deployments. Checks version-mapped CVEs, exposed services (Winbox/API/FTP/Telnet),
default/weak credentials, and firewall rule sanity — across many devices from
one view, instead of one router at a time.

## Scope discipline (read this before adding features)

This is a **read-only audit tool**. It connects to devices, reads config state,
and reports findings. It does **not** push configuration changes or attempt
active exploitation against anything outside the lab. Keep it that way until
there's a signed authorization from a real pilot customer — see the project
notes on why mixing audit and exploitation/config-push complicates both the
engineering and the sales conversation.

## Stack

- **FastAPI** — async, matters once you're polling more than a handful of
  devices concurrently
- **PostgreSQL** — device inventory, scan history, findings; SQLite is fine
  for local dev if you don't want Postgres running yet (see `config.py`)
- **librouteros** — legacy RouterOS binary API (works on 6.x and 7.x); swap
  to the REST API per-device once you confirm a device is on RouterOS 7+
- **APScheduler** — periodic scans (not wired in yet — single-run CLI first,
  scheduling once the checks themselves are solid)

## Project layout

```
app/
  main.py              FastAPI app + routes
  config.py            env-driven settings
  database.py           SQLAlchemy engine/session
  models.py             Device, ScanResult, Finding tables
  routeros_client.py    thin wrapper over librouteros
  scanner/
    version_check.py    version -> CVE matching
    service_check.py    exposed service checks (Winbox/API/FTP/Telnet)
    credential_check.py default/blank credential checks
    firewall_check.py   basic firewall rule sanity checks
    run.py              orchestrates all checks for one device
  api/
    devices.py          CRUD for device inventory
    scans.py            trigger + fetch scan results
  cve_data/
    routeros_cves.json  seed CVE data — REPLACE with NVD pull, see note in file
tests/
  test_scanner.py        checks run against a mocked device response
```

## Setup

```bash
cp .env.example .env      # fill in your CHR's IP + credentials
docker compose up -d db   # postgres only, for local dev
pip install -r requirements.txt --break-system-packages
python -m app.init_db     # creates tables
```

## Running a scan against your CHR

```bash
python -m app.scanner.run --host <chr-ip> --port 8728 --user admin --password ""
```

This runs all checks against one device and prints findings to stdout, plus
writes them to the DB if `DATABASE_URL` is set. Once this is solid against
your single CHR, add more devices via the `/devices` API and loop.

## What's NOT built yet (on purpose — don't add these until the core is solid)

- Scheduling (APScheduler wiring)
- Alerting (email/Telegram)
- PDF reporting
- Fleet-wide config push — explicitly out of scope for this product, see
  README section above
- Big data / streaming infra — not justified at this data volume, see
  project notes
