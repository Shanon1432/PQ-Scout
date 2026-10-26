"""Generate a TLS handshake with KNOWN parameters and capture it to pcap.

This is the ground-truth generator: we choose the cipher suite / group,
so we know the correct answer before the parser ever runs.
"""
import subprocess, time, sys, os
from scapy.all import AsyncSniffer, wrpcap

def run_case(name, port, server_args, client_args, outdir="data"):
    sniffer = AsyncSniffer(iface="lo", store=True)
    sniffer.start(); time.sleep(0.6)

    srv = subprocess.Popen(
        ["openssl","s_server","-accept",str(port),"-cert","data/cert.pem",
         "-key","data/key.pem","-quiet","-naccept","1"] + server_args,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(1.2)

    cli = subprocess.run(
        ["openssl","s_client","-connect",f"127.0.0.1:{port}","-servername","pqscout-lab.local"]
        + client_args,
        input=b"Q\n", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)

    time.sleep(0.8)
    pkts = sniffer.stop()
    srv.terminate()

    path = os.path.join(outdir, f"{name}.pcap")
    wrpcap(path, pkts)
    # pull what openssl itself reports, as an independent check
    out = cli.stdout.decode("utf-8","replace")
    reported = [l.strip() for l in out.splitlines()
                if l.strip().startswith(("Protocol", "Cipher", "Negotiated TLS1.3 group",
                                          "Server Temp Key"))]
    return path, len(pkts), reported

if __name__ == "__main__":
    cases = [
        # name, port, server flags, client flags   -> GROUND TRUTH we set
        ("tls13_x25519",   4433, ["-tls1_3","-groups","X25519"],        ["-tls1_3"]),
        ("tls12_ecdhe_rsa",4434, ["-tls1_2","-cipher","ECDHE-RSA-AES256-GCM-SHA384"],
                                 ["-tls1_2","-cipher","ECDHE-RSA-AES256-GCM-SHA384"]),
        ("tls12_rsa_weak", 4435, ["-tls1_2","-cipher","AES128-SHA"],
                                 ["-tls1_2","-cipher","AES128-SHA","-cipher","AES128-SHA"]),
    ]
    for name, port, sa, ca in cases:
        try:
            p, n, rep = run_case(name, port, sa, ca)
            print(f"[{name}] pcap={p} packets={n}")
            for r in rep: print(f"    openssl reports: {r}")
        except Exception as e:
            print(f"[{name}] FAILED: {e}")
