# Khud build karne ka map

## Terms, seedhe words me

- IP: network pe device/address ko identify karne ka number. Hostname uska naam;
  DNS naam se address nikalta hai. Ek hostname ke multiple IP ho sakte hain.
- Port: ek IP pe network service ka numbered endpoint, 1-65535 in this tool.
  Port 443 aksar HTTPS hota hai, lekin number se service prove nahi hoti.
- TCP: reliable byte-stream connection protocol. Connect scan me normal TCP
  connection kholne ki koshish hoti hai. Isme packets send hote hain; ye passive
  network observation nahi hai, aur server logs/alerts me dikh sakta hai.
- Socket: Python ka network endpoint object. Timeout ek operation ke wait ko
  bound karta hai. Refused connection = closed observation; timeout = unknown.
- Banner: service ka greeting/version text. Fake ya patched version ho sakta hai.
- TLS: encrypted connection protocol. Certificate server ki identity/public key
  ko trust chain se check karne me help karta hai. Certificate verified hone se
  website ka application secure prove nahi hota.
- HTTP header: response ki metadata line. CSP browser resource policy; HSTS
  HTTPS preference; X-Content-Type-Options MIME sniffing control; Referrer-Policy
  referrer info control. Header missing hone ka impact context pe depend karta hai.
- API/backend: Python service jo request validate karke scan chalata hai.
  Frontend: React browser UI. JSON: structured text format jo dono exchange karte.
- CVE: published vulnerability identifier, severity score nahi. Version match
  se actual vulnerability prove nahi hoti. Patch backports banner change bina bhi
  vulnerability fix kar sakte hain. Is draft me sirf 2 Apache advisory hints hain.

## Ek tiny connect example, line by line

Sirf apne running localhost lab ke liye:

```python
import socket
with socket.create_connection(('127.0.0.1', 8899), timeout=1) as connection:
    print('TCP connection established')
```

1. `import socket`: Python network library load hoti hai.
2. `('127.0.0.1', 8899)`: address + port tuple. Loopback = apni machine.
3. `create_connection`: normal TCP handshake try hota hai. Failure pe exception.
4. `timeout=1`: connection attempt ka wait bound. Infinite wait nahi.
5. `with`: block ke baad socket close, chahe error ho.
6. `print`: connection establish hua, bas. "Service safe/vulnerable" nahi bolta.

HTTP part me tool sirf `HEAD / HTTP/1.1` bhejta hai, response headers parse karta
hai, redirect follow nahi karta. TLS ke liye Python default verified context use
hota hai; `check_hostname=False` ya `CERT_NONE` use nahi hota. JSON report me
remote strings data hain, instructions nahi. React unhe escaped text me dikhata.

## Tere coding milestones

1. `ports()` likh: valid range, duplicates, hard cap. Checkpoint: bad ports pe no
   network call. `test_ports` aur `test_ports_reject` dekh.
2. `resolve_plan()` likh: DNS snapshot, exact written scope, non-local permission,
   metadata/link-local block. Checkpoint: mixed authorized/unauthorized DNS fail.
3. `tcp_probe()` likh: open/refused/timeout/error alag. Checkpoint: owned localhost
   listening server aur bound-not-listening socket ke tests.
4. RateGate + bounded worker pool add kar. Checkpoint: connections stagger hote
   hain; concurrency aur rate ek cheez nahi. Saare enrichment calls bhi gate use karein.
5. Passive banner read add kar: no payload, small size, strip terminal controls.
6. HTTP HEAD checker likh: fixed path, header cap + deadline, no redirect, no
   cookies. Checkpoint: local 302 fixture follow nahi hota, missing headers review.
7. Verified TLS checker add kar. Checkpoint: generated localhost CA/cert works;
   wrong trust pe stop, insecure fallback nahi.
8. `advisories.py` padh: 2 exact rules, official source, possible-only label.
   Khud rules add karne se pehle vendor affected-version record verify kar.
9. FastAPI model/gates + one-active-scan lock. Checkpoint: Origin/Host/permission
   fail; local valid request work. Public deploy abhi nahi.
10. React form + loading/error + findings + JSON export. Checkpoint: permission
    ke bina disabled, unsafe remote HTML text ki tarah render, mobile no overflow.
11. README/update tests likh. Apni understanding se code change kar, test chala,
    phir commit. Blind copy se zyada ek-ek function samajhke build kar.

## Files ka role

`scanner.py` engine/CLI, `advisories.py` curated rules, `app.py` local API,
`run.py` loopback launcher, `demo_server.py` owned fixture, `test_scanner.py`
backend/integration tests, `frontend/src/App.jsx` UI, `style.css` design.

## Aage kya missing hai

No UDP, authenticated assessment, complete service fingerprinting, complete
vulnerability database, exploit verification, multi-host jobs, persistent history,
public hosting security or owner-verification system. Ye real local working
starter hai, professional pentest ya production launch ka substitute nahi.
