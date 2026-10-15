# ScopeCheck

A working local-first defensive security workbench by Aryan: FastAPI backend,
React frontend and a dependency-free Python scan engine. Enter one hostname/IP,
choose a bounded set of TCP ports, confirm authorization, inspect observations
and export a JSON report. This is a learning project, not a production scanner
or a complete vulnerability assessment.

## Permission first

Scan only systems you own or have **written permission** to test, within the
agreed target, ports, rate and time window. A public website, reachable IP or
bug-bounty program is not blanket permission. Check the program's scope and
rules first. Do not scan a hosting provider's shared infrastructure just because
you own a site hosted there. No third-party target was scanned for this demo.

The included lab runs on localhost. Its fake Apache/2.4.49 Server header is a
**fixture**, not a vulnerable Apache installation. It demonstrates how a banner
hint can be wrong. No exploit payloads are included or sent.

## Windows quick start (Python 3.11 + Node.js 22)

Install Python and Node.js first. Open PowerShell in this project folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe run.py
```

Open **http://127.0.0.1:8765**. Keep that terminal running. In a second PowerShell
window in the same project folder:

```powershell
.\.venv\Scripts\python.exe demo_server.py
```

In the app set target `127.0.0.1`, TCP ports `8899`, HTTP HEAD ports `8899`,
leave TLS/banner ports empty and tick the permission checkbox. Click
**Run authorized check**. The lab's port should be open. The report should show
missing HTTP security headers and a **possible version match**, not a confirmed
vulnerability. Export JSON saves the report in your browser's download folder.
Stop either server with Ctrl+C. Port 8899 must be free for the fixture.

Linux/macOS: create the environment with `python3 -m venv .venv`; replace the
Windows Python path with `.venv/bin/python`. Build the same frontend, then run
`.venv/bin/python run.py`. The launcher intentionally binds only to loopback.

Beginner Hinglish walkthrough: [docs/HOW_TO_USE.md](docs/HOW_TO_USE.md).
Concepts and build roadmap: [docs/LEARNING.md](docs/LEARNING.md).

## What actually works

- TCP connect scans: open, connection refused/closed, timeout or error.
  Timeout is **not** labeled "filtered" or proof of a firewall.
- Passive banners on ports you explicitly select. Reads at most 256 bytes,
  sends no application payload and strips control characters. A banner may
  be absent, misleading or sensitive. Port numbers do not prove the service.
- TLS on selected ports: verified certificate/hostname handshake, negotiated
  protocol/cipher and expiry where available. Never disables certificate
  verification. Private CA trust failures are observations, not proof of an
  exploitable flaw. One negotiation is not a full cipher/protocol audit.
- HTTP/HTTPS `HEAD /`: status, Server header, CSP, X-Content-Type-Options,
  Referrer-Policy, frame-protection header presence and HSTS on HTTPS.
  No redirect following, login, crawling or request-body collection.
  Headers are capped at 16 KiB with a deadline. HEAD responses may differ
  from GET. Presence alone does not validate a security policy.
- Two tightly scoped Apache advisory hints: CVE-2021-41773 for reported 2.4.49,
  CVE-2021-42013 for reported 2.4.49/2.4.50. Offline rule set, **not** a live CVE
  feed. Vendor patches/backports and actual configuration require owner review.
  No claim of complete version/CVE coverage or exploitability.
- React report, open-port filter, authorization/error states and JSON export.
  Remote strings render as text, never HTML.

## Scope and safety design

Defaults: localhost, five selected TCP ports, 4 workers, max 5 new connections
per second, 1 second socket timeout. Hard limits: 128 ports, 16 workers,
10 connections/sec and 0.1-5 second timeout. Every scan/enrichment connection
shares the same rate gate. No UDP, SYN/raw-packet scans, brute force, exploitation,
DoS, credential tests or evasion. Even a light connect scan can trigger alerts.

Non-local targets require explicit authorization and numeric `--scope`/UI scope.
DNS resolves once; **every** answer must be authorized, and the chosen numeric
IP is pinned for all connections. Only that one selected address is scanned.
Unspecified, multicast and link-local addresses are rejected, including common
cloud metadata addresses. CIDRs describe permission scope, not network sweeps.
The checkbox is a user's assertion, not technical proof of permission.

The API accepts one active scan, same-origin JSON and approved localhost Host
headers. No CORS access is enabled. Reports remain in the browser until exported;
the server does not save them automatically. Do not commit exported real-target
reports: banners/headers can contain private data. There is no automatic redaction.

**Do not publish this backend as a public scanner service, bind to 0.0.0.0, or
expose it through a tunnel.** Local controls are not authentication, tenant
isolation or abuse prevention. A launchable public service would need a separate
security design, target-ownership verification, authentication, quotas, audit
controls, deployment hardening and a legal review. OS DNS resolution uses the
system resolver and may exceed socket timeouts. Closing the browser does not
cancel an already-running scan. No persistent scan jobs or automatic schedules.

## CLI

Loopback example, while the fixture is running:

```powershell
.\.venv\Scripts\python.exe scanner.py 127.0.0.1 --ports 8899 --http-ports 8899 --output lab-report.json
```

For a non-local authorized target, use its approved hostname/IP plus
`--authorized --scope <approved-numeric-IP-or-CIDR>`. Do not copy an unknown
internet target into a scan command. Use `--plan-only` to validate target/scope
without scan connections (DNS queries may still happen).

HTTP/TLS/banner lists must be subsets of the TCP port list. A port in both
HTTP and TLS lists uses HTTPS. Existing CLI report files are never overwritten.
The CLI can check localhost without the flag; the web UI/API always require
permission confirmation. Separate terminal sessions are not globally rate-limited:
run one tool instance at a time.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
cd frontend
npm test
npm run build
```

Tests cover scope rejection, all DNS addresses, parsing/bounds, rate gate,
real owned-loopback HTTP/TCP, a locally generated TLS certificate/HTTPS,
certificate failures, advisory rules, report overwrite protection, API
permission/origin/host/concurrency gates and frontend authorization/error states.
The TLS test uses OpenSSL to generate an ephemeral certificate and skips if
OpenSSL is not installed. No external scan target is needed.

## Interpreting a report / responsible disclosure

Do not assign "critical" severity to an open port or missing header. This tool
reports **observed state**, **review items** and **possible version matches**.
It does not calculate CVSS, validate vulnerabilities or certify security.
A blank report does not mean a target is secure. A company report needs owner
permission, a safe reproducible observation, scope/time details, clear uncertainty
and their published security/bug-bounty disclosure channel. Never threaten a
company, demand payment or access private data to prove a point.

## Advisory sources

- https://httpd.apache.org/security/vulnerabilities_24.html
- https://archive.apache.org/dist/httpd/CHANGES_2.4.51

Rules reviewed against these official Apache records on 16 October 2026. The
version-to-advisory hints are deliberately small and must not imply coverage
of other products or newer advisories.
