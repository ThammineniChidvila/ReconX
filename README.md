# ReconX - Unified Cybersecurity Reconnaissance Platform

ReconX is a local Flask dashboard that gathers **passive public intelligence** about a domain and offers a separate,
**strictly authorised port assessment** that only unlocks after you prove DNS ownership. Every number on the dashboard comes
from the scans stored in SQLite; nothing is hardcoded or invented.

## Features

| Area | What it does |
|---|---|
| Dashboard | Domains analysed, scans, discovered subdomains, verified targets, 7-day activity chart, status breakdown, recent scans, quick-scan bar |
| Domain intelligence | Strict validation, normalisation (URLs, ports, IDN), timestamp, resolved IPs, live per-module scan progress |
| DNS | A, AAAA, MX, NS, TXT, CNAME with per-record status (dnspython) |
| WHOIS / RDAP | Registrar, registration / expiry / updated dates, domain status, name servers. Missing data is shown as "Not available" |
| SSL / TLS | Issuer, subject, validity dates, days remaining, status, hostname verification, protocol, cipher, SANs |
| Subdomains | Passive discovery from Certificate Transparency (crt.sh). No brute forcing |
| Technology | Server, HTTP status, HTTPS availability, security headers, technologies **with evidence** for each claim |
| Authorised port assessment | DNS TXT ownership verification, then a limited TCP check of 14 fixed ports |
| History | SQLite scan history with filters; reopen any scan |
| PDF reports | Downloadable report built only from stored results, plus derived security observations |

## Technology stack
Python (Flask), SQLite, dnspython, requests, BeautifulSoup4, reportlab, plain HTML/CSS/JavaScript (no CDN, works offline once installed).

## Project structure
```
ReconX/
  app.py                  Flask routes and JSON API
  config.py               Settings, timeouts, safe port list
  modules/
    domain_validator.py   Input validation / normalisation
    net_safety.py         Blocks private/loopback/link-local/multicast/reserved IPs
    dns_analyzer.py  rdap_analyzer.py  ssl_analyzer.py
    subdomain_discovery.py  technology_detector.py
    port_assessment.py    Verification + guarded port checks
    observations.py       Evidence-based security observations
    orchestrator.py       Runs passive modules in parallel
    report_generator.py   PDF reports
  database/  db.py models.py
  templates/ static/css static/js
  reports/                Generated PDFs
  tests/                  44 mocked unit tests
```

## Installation (Windows 11, PowerShell)
```powershell
cd path\to\ReconX
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If PowerShell blocks activation: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Python 3.14 note:** all dependencies are pure Python or ship wheels for current Python versions. If any package fails to
install on 3.14, use Python 3.12 instead: `py -3.12 -m venv .venv`.

## Run
```powershell
python app.py
```
Open http://127.0.0.1:5000. The server only listens on localhost.

## Run the tests
```powershell
python -m unittest discover -s tests -t . -v
```
Tests use mocks and fixtures only - they never contact public systems.

## How to use each module
1. **Quick scan** - type a domain in the top bar and press *Run intelligence scan*. The pipeline chips show each module finishing live; you are taken to the results.
2. **Domain Intelligence** - overview of the selected scan: normalised domain, IPs, module statuses and security observations.
3. **DNS Records / WHOIS-RDAP / SSL Analysis / Subdomains / Technology Detection** - detail pages for the selected scan. Use the *Scan* drop-down to open older scans.
4. **Authorised Port Assessment** - see below.
5. **Scan History** - filter and reopen scans, download PDFs. **Reports** - download PDFs. **Settings** - view limits, clear stored data.

## DNS verification (port assessment)
1. Open *Authorised Port Assessment*, enter a domain **you control**, press *Get verification token*.
2. In your DNS provider, add a TXT record exactly as shown, e.g.
   - Name/host: `_reconx.yourdomain.com` (some providers want only `_reconx`)
   - Value: `reconx-verification=<your token>`
3. Press *Check DNS record*. DNS can take a few minutes to propagate.
4. Once verified, press *Start port assessment*. Ownership is re-checked at the moment you start.

## Security design
- Port assessment is refused unless the TXT record is found (checked again at scan time). Raw IP addresses are never accepted.
- The target is re-resolved immediately before connecting; **every** returned address must be public. Loopback, private, link-local, multicast, reserved, CGNAT and IPv4-mapped equivalents are blocked, which defeats DNS-rebinding-style answers. The scan connects to the validated IP, not the hostname.
- Only the fixed port list in `config.py` can be probed; the API accepts no custom ports. 1.5 s timeouts, 5 workers, one assessment at a time.
- HTTP inspection follows redirects manually, stays inside the target's domain and re-validates each hop's IP.
- State-changing API calls require a custom header and same-origin requests; all remote data is HTML-escaped in the UI; no secrets or file paths are returned in errors.
- No exploitation, brute forcing, credential attacks, stealth scanning or DoS functionality exists.

## Ethical-use disclaimer
Use ReconX only on domains you own or are explicitly authorised to assess. Passive modules query public sources, but the
technology and TLS modules do contact the target's public web server like a normal visitor. You are responsible for
complying with applicable laws and the terms of the services queried (rdap.org, crt.sh).

## Screenshots
Create `docs/screenshots/` and add images, then reference them here:
```markdown
![Dashboard](docs/screenshots/dashboard.png)
![Scan results](docs/screenshots/intelligence.png)
![Port assessment](docs/screenshots/ports.png)
```
Suggested shots: dashboard after 3-4 scans, a finished intelligence scan, the technology page, the port-assessment verification flow (use your own domain), and the PDF report.

## Known limitations
- HTTP technology detection validates IPs before each request but `requests` resolves the name again internally, so a very fast rebinding race is theoretically possible for that passive module. Port assessment is not affected (it connects to the validated IP).
- crt.sh and rdap.org are free public services and are sometimes slow or rate-limited; ReconX reports this as "unavailable" instead of guessing.
- Certificates that fail verification are reported as untrusted without detail fields (the standard library cannot parse unverified certificates).
- Technology detection is header/HTML-evidence based and will miss technologies that leave no trace.

## Future improvements
Scheduled rescans, scan comparison/diff, SPF/DKIM/DMARC analysis, HTTP-pinned connections for the technology module, JSON/CSV export, user accounts, Docker image.
