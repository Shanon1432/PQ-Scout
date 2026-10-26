"""Compare PQ-Scout's passive observation against Nmap's active
ssl-enum-ciphers scan of the same server.

This is NOT a like-for-like accuracy comparison -- the two tools answer
different questions, and that difference is itself the point:

  * Nmap ssl-enum-ciphers makes ONE CONNECTION PER CIPHER SUITE it tests
    (dozens of handshakes) to enumerate everything a server is willing to
    negotiate. It is thorough but active: every one of those connections
    is visible to the server and anything watching the network for it.

  * PQ-Scout makes zero connections. It never talks to the target. It
    only reports what a single real client happened to negotiate in a
    session it quietly observed -- a subset of what Nmap finds, by
    design, because that's the entire point of being passive.

The useful comparison is therefore: (a) is the ONE cipher PQ-Scout
passively observed actually a real member of the set Nmap's active probe
confirms the server supports (a correctness cross-check against an
independent, widely-trusted tool), and (b) how many connections / how
much server-visible activity did each approach need to reach its answer.
"""
import json, re, subprocess, sys, time, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import AsyncSniffer, wrpcap
from pqscout.pcap_reader import analyse_pcap

RESULTS = "results"
DATA = "data/nmap_baseline"
os.makedirs(RESULTS, exist_ok=True)
os.makedirs(DATA, exist_ok=True)

# `server` restricts only the protocol version (a realistic admin policy:
# "TLS 1.2 only"), leaving many ciphers available -- exactly what Nmap is
# enumerating. `client` is what ONE real connecting client asks for, which
# is the single data point PQ-Scout gets to passively observe. The server
# supports more than any one client happens to use; that gap is the whole
# reason this is a non-trivial check rather than a tautology.
CASES = [
    dict(name="tls12_ecdhe_rsa", port=48443, server=["-tls1_2"],
         client=["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"]),
    dict(name="tls12_rsa",       port=48444, server=["-tls1_2"],
         client=["-tls1_2", "-cipher", "AES128-SHA"]),
    dict(name="tls13_x25519",    port=48445, server=["-tls1_3"],
         client=["-tls1_3", "-groups", "X25519"]),
]

CIPHER_LINE = re.compile(r"\|\s+(TLS_\S+?)(?:\s+\(|\s+-)")


def _normalise_nmap_name(name):
    """Nmap's ssl-enum-ciphers NSE script names TLS 1.3 suites
    'TLS_AKE_WITH_<X>' instead of the IANA-registered 'TLS_<X>' that
    PQ-Scout (and RFC 8446) use -- e.g. TLS_AKE_WITH_AES_256_GCM_SHA384
    vs TLS_AES_256_GCM_SHA384. Confirmed by hand against a live TLS 1.3
    scan rather than assumed, since a naive string comparison would
    otherwise flag every correct TLS 1.3 result as a mismatch."""
    return name.replace("TLS_AKE_WITH_", "TLS_")


def run_nmap(port, server_args):
    """Active side: enumerate every cipher the server will negotiate.
    No -naccept limit -- Nmap needs many connections. Uses the SAME
    version/cipher restriction as the passive capture, so both tools are
    looking at the identical server configuration."""
    srv = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", "data/cert.pem",
         "-key", "data/key.pem", "-quiet"] + server_args,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(1.0)
    try:
        out = subprocess.run(
            ["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), "127.0.0.1"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60
        ).stdout.decode("utf-8", "replace")
    finally:
        srv.terminate()
        srv.wait(timeout=5)
    raw_ciphers = CIPHER_LINE.findall(out)
    ciphers = sorted({_normalise_nmap_name(c) for c in raw_ciphers})
    return ciphers, out


def run_pqscout_observation(case):
    """Passive side: one real client handshake, sniffed, zero interaction
    initiated by us beyond that one legitimate session. Server is the
    same version-restricted-but-otherwise-broad config Nmap scanned;
    the client picks one specific cipher out of everything the server
    would have accepted."""
    port = case["port"]
    sniffer = AsyncSniffer(iface="lo", store=True)
    sniffer.start(); time.sleep(0.4)
    srv = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", "data/cert.pem",
         "-key", "data/key.pem", "-quiet", "-naccept", "1"] + case["server"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(1.0)
    subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "pqscout-lab.local"]
        + case["client"],
        input=b"Q\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    time.sleep(0.5)
    pkts = sniffer.stop()
    srv.terminate()
    path = f"{DATA}/{case['name']}.pcap"
    wrpcap(path, pkts)
    obs = analyse_pcap(path)
    return obs[0] if obs else None


def run():
    rows = []
    for case in CASES:
        print(f"[{case['name']}] running Nmap ssl-enum-ciphers against port {case['port']} ...")
        nmap_ciphers, raw = run_nmap(case["port"], case["server"])
        print(f"    Nmap found {len(nmap_ciphers)} supported cipher(s)")

        print(f"[{case['name']}] capturing one passive PQ-Scout observation ...")
        obs = run_pqscout_observation(case)
        pq_cipher = obs.selected_cipher if obs else None

        consistent = pq_cipher in nmap_ciphers if (pq_cipher and nmap_ciphers) else None
        rows.append(dict(
            case=case["name"], port=case["port"],
            nmap_connections_made=f"~{len(nmap_ciphers)}+ (one handshake per cipher tested)",
            nmap_ciphers_found=nmap_ciphers,
            pqscout_connections_made=0,
            pqscout_observed_cipher=pq_cipher,
            pqscout_negotiated_version=obs.negotiated_version if obs else None,
            consistent_with_nmap=consistent,
        ))
        print(f"    PQ-Scout observed: {pq_cipher}  (consistent with Nmap: {consistent})\n")

    out = dict(methodology=(
        "Nmap ssl-enum-ciphers actively probes the server with one TLS "
        "handshake per cipher suite tested, to enumerate everything it "
        "supports. PQ-Scout makes zero connections and only reports what "
        "one real passively-observed session negotiated. The check here "
        "is whether PQ-Scout's single passive observation is a true "
        "member of Nmap's actively-confirmed set, and how much server-"
        "visible activity (connection count) each approach required."
    ), rows=rows)

    with open(f"{RESULTS}/nmap_baseline.json", "w") as fh:
        json.dump(out, fh, indent=2)

    print("  Case              PQ-Scout observed                        In Nmap's set?  Nmap set size")
    print("  " + "-" * 100)
    for r in rows:
        print(f"  {r['case']:<16}  {str(r['pqscout_observed_cipher']):<40}  "
              f"{str(r['consistent_with_nmap']):<14}  {len(r['nmap_ciphers_found'])}")
    print(f"\n  Written to {RESULTS}/nmap_baseline.json")
    return out


if __name__ == "__main__":
    run()
