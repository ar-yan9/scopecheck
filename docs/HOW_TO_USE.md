# ScopeCheck v0.2 kaise chalana hai

Ye local defensive workbench hai, "website hack confirm" tool nahi. Ports aur
configuration observations milte hain. Sirf apne device ya written permission
wale target pe use kar. Open port/missing header = confirmed vulnerability nahi.

## Tere existing Windows folder ko update kar

Purane run.py/demo_server.py terminals me Ctrl+C kar. VS Code terminal PowerShell:

```powershell
cd D:\MCA\PROJECT\nmap\scopecheck
git status --short
git pull --ff-only
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend
npm ci
npm run build
cd ..
.\.venv\Scripts\python.exe run.py
```

Agar Git local changes/conflict bole to stop kar, apne files delete ya reset mat
kar. ZIP download kiya tha aur `.git` nahi hai to fresh ZIP alag folder me extract
kar; purana folder backup rakh. Fresh setup ke liye README commands use kar.
Existing `.venv` dobara banane ki zarurat nahi. Python 3.11, Node.js 22 required.
Browser me http://127.0.0.1:8765 khol. Purana UI ho to Ctrl+F5 kar.

## Safe demo, bina outside scan

Dusri PowerShell terminal:

```powershell
cd D:\MCA\PROJECT\nmap\scopecheck
.\.venv\Scripts\python.exe demo_server.py
```

1. Target `127.0.0.1` rakh.
2. Port preset **Custom ports / range**, TCP ports `8899`.
3. Automatic checks tick rehne de. Optional HTTP/TLS fields bharne ki zarurat nahi.
4. **Start scope check**. Apne machine ke liye permission list/checkbox nahi chahiye.
5. Open `8899` row pe click kar. HTTP headers aur possible version hint dikhega.
   Apache banner fake lab fixture hai. Ye vulnerable Apache install nahi karta.
6. JSON structured evidence download karta hai. HTML complete open-port report
   deta hai. **Print / PDF** new tab me report kholta hai, phir Ctrl+P > Save as PDF.
7. Local history reload ke baad bhi saved reports rakhti hai. Clear se remove kar.
8. Dono terminals me Ctrl+C se band kar. Demo port already occupied ho to pehle
   check kar ki purana demo hi running hai; unknown process ko blindly kill mat kar.

## Apne laptop IP pe check

UI ke **Detected on this laptop** me apna LAN IPv4 button select kar. `ipconfig`
se bhi active adapter ka IPv4 dekh sakta hai. Tool actual interface addresses
check karta hai, poori private range ko owned nahi maanta. Apna hostname tabhi
local maana jayega jab uske sab DNS answers apni machine ke hon.
IPv6 link-local zone addresses supported nahi; IPv4/global IPv6 use kar.

Pehle Common 100 chala. Ye curated list hai. **Ports 1-1000** numeric range hai,
popularity ranking nahi. **All TCP** actual 1-65535 hai. Full scan default 50/s
pe discovery me kam-se-kam lagbhag 22 minute le sakta hai, checks/timeouts extra.
8GB RAM ke liye bounded workers hain; 65k threads nahi bante. Rate slow rakhna
fragile services ke liye better hai. No exploit ka matlab zero disruption nahi.

Progress me TCP phase ke baad open-port checks chalte hain. Cancel scan se naya
kaam rukta hai; current socket timeout tak thoda wait ho sakta hai. Cancelled
report me unscanned/pending counts dekh. Browser close karne se job cancel nahi
hota, reopen se reconnect hota hai. Server restart pe active job resume nahi hota.

## Kisi aur authorized device pe

Owner ki written permission me target, ports, rate aur time window check kar.
Permission checkbox aur approved numeric IP/CIDR scope bhar. Scope box permission
record karta hai, network range scan nahi karta. Har resolved DNS IP allowed hona
chahiye. External limit 16 workers/25 connections per second hai; owner ke rules
usse kam ho to kam hi use kar. Rate settings me apne target ke hisab se values rakh.

Automatic web/TLS checks known ports pe hote hain. Unknown service pe blindly
HTTP nahi bhejta. Known custom protocol port ho to Rate & optional protocol
overrides me HTTP/TLS/banner port daal. HTTP+TLS same port = HTTPS. TCP selection
se bahar purane override ports ignore hote hain aur report me listed hain.

Search/state filter se results dekh. Row me service basis padh: registry hint
proof nahi hai. TLS shows ek negotiated version, saare supported versions nahi.
Cookie values report me nahi rakhe jaate, flags review hote hain. Missing headers
context-dependent hain. Server header spoofed/patched ho sakta hai.

## Error samajh

- Scope/permission: actual permission verify kar, scope blindly broaden mat kar.
- TLS verify failed: private CA, hostname, expiry ya trust issue ho sakta hai;
  verification disable mat kar.
- Timeout: slow service/firewall/network kuch bhi ho sakta hai. Verdict nahi.
- Frontend blank/old: `npm ci`, `npm run build`, server restart, Ctrl+F5.
- History/report private data contain kar sakta hai. `local-data` Git ignored hai;
  exported real reports bhi GitHub pe mat daal.
- Backend public internet pe expose/tunnel/bind 0.0.0.0 mat kar.

Company report sirf policy wale private security channel pe bhej. Permission,
time/scope, observed behavior aur uncertainty likh. Sirf open port se "hack kar
diya" mat bol. Private data access/download mat kar. Payment guaranteed nahi.
