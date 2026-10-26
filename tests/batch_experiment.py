"""Ground-truth experiment harness for PQ-Scout.

Generates a matrix of TLS handshakes with KNOWN parameters, captures each
to pcap, and records the intended configuration as ground truth.

Ground truth is *constructed*: we set the server/client configuration, so
the correct answer is known before the tool is ever run.
"""
import json, os, socket, subprocess, sys, time
from scapy.all import AsyncSniffer, wrpcap

OUT = "data/batch"
BASE_PORT = 15000

# ---------------------------------------------------------------- matrix
TLS13_SUITES = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256"]
TLS13_GROUPS = ["X25519", "P-256", "P-384", "P-521"]

TLS12_SUITES = [
    # (openssl name, expected IANA name, kex, sig)
    ("ECDHE-RSA-AES256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA"),
    ("ECDHE-RSA-AES256-SHA384",     "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", "RSA"),
    ("ECDHE-RSA-AES128-SHA256",     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", "RSA"),
    ("ECDHE-RSA-AES256-SHA",        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",    "ECDHE", "RSA"),
    ("ECDHE-RSA-AES128-SHA",        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",    "ECDHE", "RSA"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", "RSA"),
    ("DHE-RSA-AES256-GCM-SHA384",   "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",   "DHE",   "RSA"),
    ("DHE-RSA-AES128-GCM-SHA256",   "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",   "DHE",   "RSA"),
    ("DHE-RSA-AES256-SHA256",       "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",   "DHE",   "RSA"),
    ("DHE-RSA-AES128-SHA",          "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",      "DHE",   "RSA"),
    ("DHE-RSA-CHACHA20-POLY1305",   "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","DHE","RSA"),
    ("AES256-GCM-SHA384",           "TLS_RSA_WITH_AES_256_GCM_SHA384",       "RSA",   "RSA"),
    ("AES128-GCM-SHA256",           "TLS_RSA_WITH_AES_128_GCM_SHA256",       "RSA",   "RSA"),
    ("AES256-SHA256",               "TLS_RSA_WITH_AES_256_CBC_SHA256",       "RSA",   "RSA"),
    ("AES128-SHA256",               "TLS_RSA_WITH_AES_128_CBC_SHA256",       "RSA",   "RSA"),
    ("AES256-SHA",                  "TLS_RSA_WITH_AES_256_CBC_SHA",          "RSA",   "RSA"),
    ("AES128-SHA",                  "TLS_RSA_WITH_AES_128_CBC_SHA",          "RSA",   "RSA"),
]
GROUP_ALIAS = {"X25519": "x25519", "P-256": "secp256r1",
               "P-384": "secp384r1", "P-521": "secp521r1"}


def build_matrix():
    cases, port = [], BASE_PORT
    # --- TLS 1.3: suite x group
    for suite in TLS13_SUITES:
        for group in TLS13_GROUPS:
            cases.append(dict(
                name=f"tls13_{suite.replace('TLS_','').lower()}_{group.lower()}",
                port=port, kind="tls",
                server=["-tls1_3", "-ciphersuites", suite, "-groups", group],
                client=["-tls1_3", "-ciphersuites", suite, "-groups", group],
                truth=dict(version="TLS 1.3", cipher=suite, kex="ECDHE",
                           group=GROUP_ALIAS[group])))
            port += 1
    # --- TLS 1.2: full suite sweep
    for oname, iana, kex, sig in TLS12_SUITES:
        cases.append(dict(
            name=f"tls12_{oname.lower().replace('-','_')}",
            port=port, kind="tls",
            server=["-tls1_2", "-cipher", f"{oname}:@SECLEVEL=0"],
            client=["-tls1_2", "-cipher", f"{oname}:@SECLEVEL=0"],
            truth=dict(version="TLS 1.2", cipher=iana, kex=kex, group=None)))
        port += 1
    # --- legacy protocol versions (version-detection cases)
    LEGACY = [("-tls1",  "TLS 1.0"), ("-tls1_1", "TLS 1.1")]
    LEGACY_SUITES = [("AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA"),
                     ("AES256-SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "RSA"),
                     ("DES-CBC3-SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA")]
    for flag, vname in LEGACY:
        for oname, iana, kex in LEGACY_SUITES:
            cases.append(dict(
                name=f"{vname.replace(' ','').replace('.','_').lower()}_{oname.lower().replace('-','_')}",
                port=port, kind="tls",
                server=[flag, "-cipher", f"{oname}:@SECLEVEL=0"],
                client=[flag, "-cipher", f"{oname}:@SECLEVEL=0"],
                truth=dict(version=vname, cipher=iana, kex=kex, group=None)))
            port += 1
    # --- negative cases: no TLS handshake present at all
    for i, kind in enumerate(["plain_http", "random_bytes", "truncated_hello", "http_post", "binary_stream"]):
        cases.append(dict(name=f"neg_{kind}", port=port, kind=kind,
                          server=[], client=[],
                          truth=dict(version=None, cipher=None, kex=None, group=None)))
        port += 1
    return cases


# ------------------------------------------------------------- execution
def _negative_traffic(kind, port):
    """Generate non-TLS traffic so we can measure false positives."""
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1)

    def client():
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
        if kind == "plain_http":
            c.send(b"GET /index.html HTTP/1.1\r\nHost: lab.local\r\n\r\n")
        elif kind in ("random_bytes", "binary_stream"):
            c.send(os.urandom(512))
        elif kind == "http_post":
            c.send(b"POST /api/v1/login HTTP/1.1\r\nHost: lab.local\r\n"
                   b"Content-Type: application/json\r\nContent-Length: 21\r\n\r\n"
                   b'{"user":"lab","p":1}')
        else:  # truncated_hello: a TLS record header with a body that never arrives
            c.send(bytes([0x16, 0x03, 0x01, 0x02, 0x00]) + os.urandom(40))
        time.sleep(0.3)
        try: c.recv(1024)
        except Exception: pass
        c.close()

    import threading
    t = threading.Thread(target=client, daemon=True); t.start()
    conn, _ = srv.accept()
    data = conn.recv(4096)
    if kind == "plain_http":
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    else:
        conn.send(os.urandom(64))
    time.sleep(0.3); conn.close(); srv.close(); t.join(timeout=3)


def run_case(case):
    sniffer = AsyncSniffer(iface="lo", store=True)
    sniffer.start(); time.sleep(0.45)
    try:
        if case["kind"] == "tls":
            srv = subprocess.Popen(
                ["openssl", "s_server", "-accept", str(case["port"]),
                 "-cert", "data/cert.pem", "-key", "data/key.pem",
                 "-quiet", "-naccept", "1"] + case["server"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL)
            time.sleep(0.9)
            subprocess.run(
                ["openssl", "s_client", "-connect", f"127.0.0.1:{case['port']}",
                 "-servername", "pqscout-lab.local"] + case["client"],
                input=b"Q\n", stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=15)
            time.sleep(0.5); srv.terminate()
        else:
            _negative_traffic(case["kind"], case["port"])
            time.sleep(0.4)
    finally:
        pkts = sniffer.stop()

    # keep only this case's port so pcaps stay clean
    keep = [p for p in pkts if p.haslayer("TCP") and
            (p["TCP"].sport == case["port"] or p["TCP"].dport == case["port"])]
    path = os.path.join(OUT, f"{case['name']}.pcap")
    wrpcap(path, keep if keep else pkts)
    return path, len(keep)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    matrix = build_matrix()
    print(f"Matrix: {len(matrix)} cases "
          f"({sum(1 for c in matrix if c['kind']=='tls')} TLS, "
          f"{sum(1 for c in matrix if c['kind']!='tls')} negative)")
    record = []
    for i, case in enumerate(matrix, 1):
        try:
            path, n = run_case(case)
            case["pcap"], case["packets"], case["ok"] = path, n, True
            print(f"  [{i:>2}/{len(matrix)}] {case['name']:<46} {n:>3} pkts")
        except Exception as e:
            case["ok"] = False; case["error"] = str(e)[:80]
            print(f"  [{i:>2}/{len(matrix)}] {case['name']:<46} FAILED: {e}")
        record.append({k: v for k, v in case.items()
                       if k in ("name","port","kind","truth","pcap","packets","ok","error")})
    with open(os.path.join(OUT, "ground_truth.json"), "w") as fh:
        json.dump(record, fh, indent=2)
    print(f"\nGround truth written to {OUT}/ground_truth.json")
