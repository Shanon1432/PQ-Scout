"""Post-quantum path test: does PQ-Scout correctly recognise a REAL
post-quantum hybrid handshake (X25519MLKEM768) and score it LOW?

The 41-case batch could not test this: OpenSSL 3.0 cannot negotiate
ML-KEM, so the PQ_SAFE_GROUPS branch of the HNDL scorer was never
exercised by real traffic. Go 1.24's crypto/tls supports X25519MLKEM768,
so tests/pqtls/pqtls.go generates the handshakes here.

Ground truth is by construction, as in the main batch: each server is
configured to accept exactly ONE key-exchange group, while the client
offers several (a realistic client). A successful handshake can only
have used the server's one group.
"""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scapy.all import AsyncSniffer, wrpcap
from pqscout.pcap_reader import analyse_pcap
from pqscout.hndl_score import score_observation

HERE = os.path.dirname(os.path.abspath(__file__))
DATA, RESULTS = "data/pq_hybrid", "results"
os.makedirs(DATA, exist_ok=True); os.makedirs(RESULTS, exist_ok=True)
BIN = os.path.join(DATA, "pqtls_bin")

CASES = [
    # name, port, server accepts, client offers, expected group, expected band
    ("pq_hybrid_x25519mlkem768", 19443, "mlkem",  "mlkem,x25519",      "X25519MLKEM768", "LOW"),
    ("classical_x25519",         19444, "x25519", "mlkem,x25519",      "x25519",         "HIGH"),
    ("classical_p256_via_hrr",   19445, "p256",   "mlkem,x25519,p256", "secp256r1",      "HIGH"),
]


def build():
    subprocess.run(["go", "build", "-o", os.path.abspath(BIN), "pqtls.go"],
                   cwd=os.path.join(HERE, "pqtls"), check=True)


def run():
    build()
    rows = []
    for name, port, srv, cli, exp_group, exp_band in CASES:
        sniffer = AsyncSniffer(iface="lo", store=True)
        sniffer.start(); time.sleep(0.5)
        go = subprocess.run([BIN, "-port", str(port), "-server", srv, "-client", cli],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        time.sleep(0.5)
        pkts = sniffer.stop()
        path = f"{DATA}/{name}.pcap"
        wrpcap(path, pkts)

        obs_list = analyse_pcap(path)
        obs = obs_list[0] if obs_list else None
        group = obs.named_group if obs else None
        score, band, why = score_observation(obs) if obs else (None, None, "no handshake")
        ok = (group == exp_group and band == exp_band)
        rows.append(dict(case=name, server_accepts=srv, client_offers=cli,
                         go_reported=go.stdout.decode().strip(),
                         expected_group=exp_group, observed_group=group,
                         expected_band=exp_band, observed_band=band, score=score,
                         rationale=why, offered_groups=obs.offered_groups if obs else None,
                         hello_retry=obs.hello_retry if obs else None,
                         correct=ok))
        print(f"[{name}] expected {exp_group}/{exp_band} -> observed {group}/{band} "
              f"score={score}  {'CORRECT' if ok else 'MISMATCH'}")
        print(f"    client offered: {obs.offered_groups if obs else None}"
              f"   HelloRetryRequest: {obs.hello_retry if obs else None}")

    with open(f"{RESULTS}/pq_hybrid.json", "w") as fh:
        json.dump(dict(generator="Go %s crypto/tls" % subprocess.run(
            ["go", "version"], stdout=subprocess.PIPE).stdout.decode().split()[2],
            rows=rows), fh, indent=2)
    print(f"\n  {sum(r['correct'] for r in rows)}/{len(rows)} correct; "
          f"written to {RESULTS}/pq_hybrid.json")


if __name__ == "__main__":
    run()
