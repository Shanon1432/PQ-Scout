"""Check every CIC-IDS2017 (Experiment 7) number quoted in the report and in
results/cicids2017_findings.md against the results files.

Run from the project folder:   python tests/check_cicids_numbers.py
"""
import collections, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
J = lambda p: json.load(open(p))
a, b = J("results/cicids2017.json"), J("results/cicids2017_before_fix.json")
xa, xb = a["wireshark_cross_check"], b["wireshark_cross_check"]
pf = a["prefilter"]
cbom = J("results/cicids2017_cbom.json")
before_txt = open("results/cicids2017_cbom_validation_before_fix.txt").read()

P = lambda c, n: next(p["value"] for p in c["properties"] if p["name"] == n)
assets = collections.defaultdict(list)
for c in cbom["components"]:
    assets[P(c, "pqscout:asset")].append(c)
ports = collections.Counter(k.rsplit(":", 1)[1] for k in assets)
crit = [k for k, cs in assets.items() if any(P(c, "pqscout:hndlBand") == "CRITICAL" for c in cs)]
w = a["with_server_hello"]

checks = [
    ("Input: 8,839,309,056 bytes, 9,997,874 packets, pcapng",
     (pf["input_bytes"], pf["packets_read"], pf["input_format"]) == (8839309056, 9997874, "pcapng")),
    ("Prefilter kept 52,544 connections / 581,728 packets",
     (pf["tls_connections_kept"], pf["packets_kept"]) == (52544, 581728)),
    ("52,536 handshakes observed, 52,223 with a ServerHello",
     (a["tls_handshakes_observed"], w) == (52536, 52223)),
    ("Wireshark decoded both hellos in 52,164; PQ-Scout found all 52,164 (0 missed)",
     (xa["tshark_connections_with_client_and_server_hello"], xa["pqscout_found_same_connection"],
      xa["missed_by_pqscout"]) == (52164, 52164, 0)),
    ("Version agreement 52,162 / 52,164 after the fix",
     (xa["agreement"]["version"]["agree"], xa["agreement"]["version"]["compared"]) == (52162, 52164)),
    ("Cipher agreement 52,162 / 52,164 after the fix",
     (xa["agreement"]["cipher"]["agree"], xa["agreement"]["cipher"]["compared"]) == (52162, 52164)),
    ("59 connections reported only by PQ-Scout", xa["pqscout_only"] == 59),
    ("Before fix: version agreement 43,616 / 52,158 (8,320 blank, 222 different)",
     (xb["agreement"]["version"]["agree"], xb["agreement"]["version"]["compared"],
      xb["disagreement_kind"].get("version:blank"), xb["disagreement_kind"].get("version:different"))
     == (43616, 52158, 8320, 222)),
    ("Before fix: 6 missed, 8,348 incomplete; after: 0 missed, 186 incomplete",
     (xb["missed_by_pqscout"], b["incomplete_captures"], xa["missed_by_pqscout"], a["incomplete_captures"])
     == (6, 8348, 0, 186)),
    ("Key exchange: ECDHE 44,017 / RSA 6,378 / DHE 1,674 / unknown 154",
     a["key_exchange"] == {"ECDHE": 44017, "RSA": 6378, "DHE": 1674, "None": 154}),
    ("Versions: TLS 1.2 48,584 / TLS 1.0 3,609 / TLS 1.1 30",
     a["tls_versions"] == {"TLS 1.2": 48584, "TLS 1.0": 3609, "TLS 1.1": 30}),
    ("Percentages: ECDHE 84.3%, RSA 12.2%, TLS 1.0 6.9%",
     (round(44017 / w * 100, 1), round(6378 / w * 100, 1), round(3609 / w * 100, 1)) == (84.3, 12.2, 6.9)),
    ("No post-quantum groups seen", a["post_quantum_groups_seen"] == 0),
    ("6,803 server assets: 6,768 on 443, 30 on 465",
     (len(assets), ports["443"], ports["465"]) == (6803, 6768, 30)),
    ("Bands per asset: CRITICAL 30 (all port 465), HIGH 6,742, MEDIUM 31",
     a["hndl_band_per_asset"] == {"HIGH": 6742, "MEDIUM": 31, "CRITICAL": 30}
     and all(k.endswith(":465") for k in crit) and len(crit) == 30),
    ("1,028 assets used RSA; 548 used more than one key exchange; 934 negotiated TLS 1.0",
     (sum(any(P(c, "pqscout:keyExchange") == "RSA" for c in cs) for cs in assets.values()),
      sum(len({P(c, "pqscout:keyExchange") for c in cs}) > 1 for cs in assets.values()),
      sum(any(c["cryptoProperties"]["protocolProperties"].get("version") == "TLS 1.0" for c in cs)
          for cs in assets.values())) == (1028, 548, 934)),
    ("5 suites missing from the table, 154 connections",
     (len(a["suites_not_in_pqscout_table"]), sum(a["suites_not_in_pqscout_table"].values())) == (5, 154)),
    ("CBOM has 10,630 components; before the fix it failed validation",
     len(cbom["components"]) == 10630 and "Result: INVALID" in before_txt and "uniqueItems" in before_txt),
]

passed = 0
for text, ok in checks:
    passed += bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {text}")
print(f"\n  {passed}/{len(checks)} CIC-IDS2017 figures match the evidence")
print("  (CBOM schema validity: run  python tests/validate_cbom.py)")
sys.exit(0 if passed == len(checks) else 1)
