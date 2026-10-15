# ScopeCheck kaise chalana hai

## Pehle ye samajh

Ye "website hack karke vulnerability confirm" karne wala tool nahi hai.
Ye ports aur configuration dekhne ka local workbench hai. Bina permission kisi
company ka IP mat daalna. Apni website agar GitHub/Cloudflare pe hosted hai to
us hosting infrastructure ko scan karne ka permission apne aap nahi milta.

## Windows pe first run

1. Python 3.11 aur Node.js 22 install kar. `py -3.11 --version` aur `node --version`
   se check kar. GitHub repo ZIP download karke extract kar, ya Git se clone kar.
2. Project folder me PowerShell khol. README ke quick-start commands ek-ek karke
   chala. Virtual environment alag Python packages rakhta hai; system ko nahi
   badalta. `npm ci` locked frontend packages install karta hai. `npm run build`
   browser ke liye frontend ready karta hai.
3. `run.py` chalne de. Browser me http://127.0.0.1:8765 khol.
4. Dusri PowerShell window me `demo_server.py` chala. Ye tera local test server hai.
5. Target `127.0.0.1`, TCP ports `8899`, optional HTTP ports `8899` rakh.
   TLS/banner blank. Permission box tick kar, phir check chala.
6. Port open aayega. Missing headers aayenge. Apache version hint bhi aayega,
   lekin wo demo ka **fake banner** hai, real vulnerable Apache nahi. Isi liye
   tool "possible" bolta hai. Screenshot ko confirmed bug mat samajh.
7. Export JSON se report download kar. JSON structured text hota hai, PDF nahi.
   Real company ka report private rakh; GitHub pe upload mat karna.
8. Dono terminal me Ctrl+C se servers band kar.

## Apne authorized device ke liye

Pehle owner ki written permission le: kaunsa hostname/IP, kaunse ports, kitni
rate aur kis time pe check kar sakta hai. Uske approved numeric IP/CIDR ko scope
box me daal. CIDR ek address range notation hai, tool poori range scan nahi karta.
Agar DNS ke kisi address ka permission nahi hai to tool ruk jayega.

- TCP ports: sirf wo ports jo permission me hain.
- HTTP ports: jin ports pe HTTP service expect karta hai. Tool `HEAD /` bhejta hai.
- TLS ports: jahan TLS expected hai. HTTP + TLS dono list me same port = HTTPS.
- Banner ports: tool chup rehke service ka opening text sunta hai, 256 bytes tak.

Har list me wahi ports daal jo TCP list me bhi hain. Closed port pe extra checks
nahi chalte. Server ka naam/version reliable proof nahi hai. Missing header bhi
har situation me exploitable bug nahi hota.

## Agar error aaye

- "Permission": checkbox tick nahi hua. Sirf actual permission hone pe tick kar.
- "Scope": har resolved non-local IP scope me hona chahiye. Scope badha ke
  permission bypass mat kar; pehle permission verify kar.
- "Port already in use": purana demo/server band kar, phir dobara chala.
- TLS certificate verify nahi hua: private CA, hostname mismatch, expiry ya
  trust issue ho sakta hai. Verification off mat kar.
- Timeout: device slow, service silent, firewall, network problem, kuch bhi ho
  sakta hai. Confirmed filtering/vulnerability ka verdict mat de.
- Frontend blank: `npm ci` aur `npm run build` ke baad Python server restart kar.
- Ek scan running ho to wait kar. Browser close karne se backend scan cancel nahi
  hota. Limit ke andar complete hone de; zarurat ho to local server Ctrl+C se rok.

## Company ko kaise batana

Pehle program scope aur disclosure policy padh. Unke security channel pe private
report bhej: permission/scope, time, observed behavior, safe reproduction,
possible impact aur uncertainty. "Maine hack kar diya" mat bolna jab sirf port
open dekha ho. Payment guaranteed nahi hota. Kisi ka data access/download mat kar.
