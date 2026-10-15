# ScopeCheck v0.2

Local-first defensive security workbench by Aryan. FastAPI + React, a bounded
concurrent TCP engine and local SQLite report history. Inspect your own laptop
or an explicitly authorized target. Observations are **not confirmed vulnerabilities**.
This is a working learning project, not a complete pentest or production service.

## Windows quick start

Python 3.11 and Node.js 22 required. In PowerShell inside the project:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe run.py
```

Open http://127.0.0.1:8765. Keep the terminal running. In a second terminal:

```powershell
.\.venv\Scripts\python.exe demo_server.py
```

Choose target `127.0.0.1`, preset **Custom**, ports `8899`. Keep automatic checks
on and click **Start scope check**. No permission checkbox/IP list is needed for
actual own-machine addresses. Click the open-port row for HTTP observations.
The lab's Apache version is a fake fixture, **not vulnerable Apache**. Stop the
servers with Ctrl+C. No outside target is needed for this demo.

Already installed? Stop both servers, run `git pull --ff-only`, reinstall
requirements, rebuild frontend using `npm ci` and `npm run build`, then restart.
See [Windows walkthrough](docs/HOW_TO_USE.md) and [learning map](docs/LEARNING.md).
On Linux/macOS use `python3 -m venv .venv` and `.venv/bin/python`.

## What works

- Full TCP port range **1-65535**, custom ranges, curated **Common 100**,
  **Ports 1-1000** and **All TCP** presets. Common 100 is our explicit list,
  not Nmap's measured ranking; 1-1000 is numeric, not the top 1000 by popularity.
- Background jobs, progress, cooperative cancellation, browser reconnect,
  coverage counts and completed/cancelled/failed states. Cancelled reports
  show unscanned ports and pending enrichment; they are not complete scans.
- Actual interface enumeration: loopback, laptop IPv4/IPv6 and its hostname
  when all DNS answers are local. A private subnet is **not** assumed owned.
  IPv6 link-local scope-zone addresses are not supported; use IPv4 or global IPv6.
- Service-aware automatic checks on discovered open ports. Known web/TLS port
  hints select HTTP/TLS; greeting ports select passive reads. Unknown protocols
  are **not blindly sent HTTP/TLS**. Manual protocol overrides are available.
  Overrides outside the TCP selection are ignored and listed in the report,
  not allowed to break a new scan because an old form field was left filled.
- Service names distinguish observed HTTP/SSH greetings from port-number hints.
  TCP states: open, refused/closed, timeout or error. Timeout is not proof of filtering.
- HTTP/HTTPS `HEAD /`: status, unverified Server header, CSP, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, frame-protection
  presence and HTTPS HSTS. Cookie Secure/HttpOnly/SameSite attributes, **not values**.
  No redirects, login, crawling or response-body collection. Header cap 16 KiB.
  Missing headers are review items; presence alone does not validate policy.
- Verified TLS handshake, negotiated protocol/cipher, subject/issuer and expiry
  review. No insecure fallback. This reports **one negotiated version**, not a
  complete supported-protocol/cipher audit. Private CA failures need owner review.
- Passive greetings: maximum 256 bytes, control characters removed, no payload.
  Text can be misleading or sensitive. Port number alone does not prove service.
- Two Apache advisory hints: reported 2.4.49 maps to CVE-2021-41773/42013;
  2.4.50 maps to CVE-2021-42013. Offline exact rules, not a full/live CVE feed.
  Spoofing, patches and configuration require review. No exploit is attempted.
- Search, state filters, pagination, row details and raw observations. Remote
  text is escaped. JSON export includes all observed states; self-contained HTML
  and its Print/PDF view include every open port independent of the UI filter.
  **PDF uses browser Print > Save as PDF**, not a native server PDF generator.
- Local history: newest 20 reports, retained up to 7 days, SQLite under
  `local-data/history.sqlite3`. Clear in the UI. Reports may contain private data.
  `SCOPECHECK_HISTORY_DB` can change the path. Git ignores local-data and reports.

## Permission and operating limits

Use only systems you own or have **written permission** to test. Permission must
cover target, ports, time and rate. A public site, reachable IP or bug-bounty
listing is not blanket permission. Owning a hosted website does not mean owning
its provider's infrastructure. Read program rules first.

The web UI defaults to 32 workers, 50 new connections/second, 1s timeout. Own-machine
limits: 128 workers, 200 connections/second, .1-5s timeout. External authorized
jobs: at most 16 workers and 25 connections/second; lower them to the owner's
rules. A single shared rate gate covers discovery and checks. The executor has
bounded pending work, not 65,535 live threads/futures. Defaults suit an 8GB laptop,
but measured memory and completion time depend on the OS and services.
At 50 connections/sec a full discovery alone needs at least about 22 minutes;
timeouts and enrichment can add more. Lower rate is safer for fragile services.

Non-owned addresses need the permission checkbox and numeric approved IP/CIDR
scope. **Every** DNS answer must be authorized; one numeric IP is pinned and
scanned, not a whole network. Rejects unspecified, multicast and non-owned
link-local/metadata targets. A checkbox is an assertion, not proof of permission.

No UDP, raw SYN scan, exploitation, brute force, credential tests, evasion or DoS.
A connect scan still sends traffic, can trigger alerts and can disturb a fragile
service. Never promise zero impact. Run only one instance: separate processes
are not globally rate-limited. OS DNS lookup may exceed socket timeout.

The API is loopback-only with Host/Origin/JSON gates and one active scan.
Closing the tab does not cancel the job; reopening reconnects while the server
is alive. Use Cancel scan. Restarting the server stops active work; completed
history persists, but unfinished jobs are not resumed.

**Do not bind to 0.0.0.0, expose through a tunnel or deploy as a public scanner.**
Local controls are not authentication, ownership verification or tenant isolation.
Do not commit real-target reports or share them outside agreed scope.

## CLI

```powershell
.\.venv\Scripts\python.exe scanner.py 127.0.0.1 --ports 8899 --output lab-report.json
.\.venv\Scripts\python.exe scanner.py 127.0.0.1 --ports common100 --plan-only
```

Presets: `common100`, `first1000`, `all`, or `1-65535`. `--plan-only` resolves and
validates without scan connections (DNS can still happen). The CLI keeps slower
4-worker/5-per-second defaults; `--workers` and `--rate` can raise them within
scope limits. `--http-ports`, `--tls-ports`, `--banner-ports` override protocols;
HTTP+TLS on the same port means HTTPS. Existing output files are never overwritten.
Non-owned targets need `--authorized --scope <approved-IP-or-CIDR>`.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm test
npm run build
```

Tests include real localhost TCP/HTTP and generated-certificate TLS/HTTPS, scope
and DNS gates, full-range engine with mocked connections, bounded/cancellable
work, history reload, escaped exports, cookie-value omission and API/UI gates.
OpenSSL-dependent TLS tests skip if OpenSSL is missing. No arbitrary remote scan.
CI runs backend on Windows/Ubuntu Python 3.11/3.12 and tests/builds frontend.

## Responsible disclosure

Open ports and missing headers are not automatically bugs. Do not assign
critical severity or claim a breach from these results. A blank report is not
proof of security. Use an owner's published private disclosure channel, within
permission, with timestamp/scope, reproducible observation and uncertainty.
Do not access private data, threaten a company or demand payment.

## Advisory sources

- https://httpd.apache.org/security/vulnerabilities_24.html
- https://archive.apache.org/dist/httpd/CHANGES_2.4.51

Rules reviewed against these official records on 16 October 2026. Two exact
rules do not imply coverage of other products or newer advisories.
