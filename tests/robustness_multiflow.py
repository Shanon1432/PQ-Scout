"""Robustness test: many concurrent TLS connections in ONE capture.

The easy case is one handshake per pcap. Real traffic interleaves many
flows, so this tests whether stream reassembly correctly separates and
attributes each connection.
"""
import json, subprocess, threading, time, os, sys
from scapy.all import AsyncSniffer, wrpcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pqscout import analyse_pcap

CONFIGS = [
    (17001, ["-tls1_3","-ciphersuites","TLS_AES_256_GCM_SHA384","-groups","X25519"],
            "TLS 1.3", "TLS_AES_256_GCM_SHA384", "x25519"),
    (17002, ["-tls1_3","-ciphersuites","TLS_AES_128_GCM_SHA256","-groups","P-384"],
            "TLS 1.3", "TLS_AES_128_GCM_SHA256", "secp384r1"),
    (17003, ["-tls1_2","-cipher","ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0"],
            "TLS 1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", None),
    (17004, ["-tls1_2","-cipher","DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0"],
            "TLS 1.2", "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", None),
    (17005, ["-tls1_2","-cipher","AES128-SHA:@SECLEVEL=0"],
            "TLS 1.2", "TLS_RSA_WITH_AES_128_CBC_SHA", None),
    (17006, ["-tls1_2","-cipher","ECDHE-RSA-CHACHA20-POLY1305:@SECLEVEL=0"],
            "TLS 1.2", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", None),
    (17007, ["-tls1","-cipher","AES256-SHA:@SECLEVEL=0"],
            "TLS 1.0", "TLS_RSA_WITH_AES_256_CBC_SHA", None),
    (17008, ["-tls1_1","-cipher","AES128-SHA:@SECLEVEL=0"],
            "TLS 1.1", "TLS_RSA_WITH_AES_128_CBC_SHA", None),
]

def main():
    sniffer = AsyncSniffer(iface="lo", store=True); sniffer.start(); time.sleep(0.5)
    servers = []
    for port, flags, *_ in CONFIGS:
        servers.append(subprocess.Popen(
            ["openssl","s_server","-accept",str(port),"-cert","data/cert.pem",
             "-key","data/key.pem","-quiet","-naccept","1"] + flags,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL))
    time.sleep(1.5)

    def connect(port, flags):
        subprocess.run(["openssl","s_client","-connect",f"127.0.0.1:{port}",
                        "-servername","pqscout-lab.local"] + flags,
                       input=b"Q\n", stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)

    threads = [threading.Thread(target=connect, args=(p, f)) for p, f, *_ in CONFIGS]
    for t in threads: t.start()          # fire all at once -> interleaved packets
    for t in threads: t.join()
    time.sleep(1.0)

    pkts = sniffer.stop()
    for s in servers: s.terminate()
    keep = [p for p in pkts if p.haslayer("TCP") and
            (p["TCP"].sport in [c[0] for c in CONFIGS] or
             p["TCP"].dport in [c[0] for c in CONFIGS])]
    path = "data/multiflow.pcap"; wrpcap(path, keep)

    obs = analyse_pcap(path)
    found = {o.dport: o for o in obs if o.dport in [c[0] for c in CONFIGS]}
    print(f"\n  Single capture: {len(keep)} packets, {len(CONFIGS)} concurrent connections")
    print(f"  Flows recovered: {len(found)}/{len(CONFIGS)}\n")
    print(f"  {'PORT':<7}{'EXPECTED CIPHER':<48}{'MATCH':<7}{'VER':<6}{'GROUP'}")
    print("  " + "-"*90)
    ok = 0
    for port, _, ver, cipher, group in CONFIGS:
        o = found.get(port)
        if not o:
            print(f"  {port:<7}{cipher:<48}{'MISS':<7}"); continue
        good = (o.selected_cipher == cipher and o.negotiated_version == ver
                and o.named_group == group)
        ok += good
        print(f"  {port:<7}{cipher:<48}{'OK' if good else 'FAIL':<7}"
              f"{str(o.negotiated_version):<6}{o.named_group}")
    print(f"\n  Correctly attributed: {ok}/{len(CONFIGS)}\n")
    json.dump({"connections": len(CONFIGS), "packets": len(keep),
               "flows_recovered": len(found), "correct": ok},
              open("results/multiflow.json","w"), indent=2)

if __name__ == "__main__":
    main()
