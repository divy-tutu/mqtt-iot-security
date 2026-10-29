"""Live HTTP session and TLS identity checks. No passwords printed."""
import http.cookiejar
import json
import ssl
import socket
import urllib.error
import urllib.request
from pathlib import Path

password=Path("/runtime/login.txt").read_text().split("Password: ",1)[1].strip()
rows=[]
def request(opener,url,data=None,headers=None):
    req=urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,
                               headers=headers or ({"Content-Type":"application/json"} if data is not None else {}))
    try:
        with opener.open(req,timeout=5) as response:
            return response.status,json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code,None
for profile in ("baseline","hardened"):
    base=f"http://{profile}-gateway:8000"
    opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    checks=[
        ("unauthenticated-read",request(opener,base+"/snapshot")[0]==401),
        ("unauthenticated-command",request(opener,base+"/command",{"cmd":"UNLOCK"})[0]==401),
        ("wrong-login",request(opener,base+"/login",{"username":"admin","password":"wrong"})[0]==401),
        ("valid-login",request(opener,base+"/login",{"username":"admin","password":password})[0]==200),
        ("session-read",request(opener,base+"/snapshot")[0]==200),
        ("cross-site-command",request(opener,base+"/command",{"cmd":"LOCK"},{"Content-Type":"application/json","Sec-Fetch-Site":"cross-site"})[0]==403),
        ("invalid-command",request(opener,base+"/command",{"cmd":"OPEN"})[0]==400),
        ("logout",request(opener,base+"/logout",{})[0]==200),
        ("logged-out-read",request(opener,base+"/snapshot")[0]==401),
    ]
    rows.extend({"profile":profile,"check":name,"passed":passed} for name,passed in checks)
for label,context,hostname in (
    ("untrusted-ca",ssl.create_default_context(),"hardened-broker"),
    ("wrong-hostname",ssl.create_default_context(cafile="/runtime/public/ca.crt"),"not-the-broker")):
    rejected=False
    try:
        with socket.create_connection(("hardened-broker",8883),timeout=5) as sock:
            with context.wrap_socket(sock,server_hostname=hostname):
                pass
    except ssl.SSLCertVerificationError:
        rejected=True
    rows.append({"profile":"hardened","check":label,"passed":rejected})
Path("/results/api-tls.json").write_text(json.dumps(rows,indent=2))
print(json.dumps(rows,indent=2))
raise SystemExit(0 if all(r["passed"] for r in rows) else 1)

