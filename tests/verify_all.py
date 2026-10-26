"""Re-check every experiment from its SAVED captures -- works on Windows.

The experiment scripts (batch_experiment, stress_experiment, nmap_baseline,
pq_hybrid_experiment) have to capture live loopback traffic, which needs
Linux/WSL. This script needs no capture at all: it re-runs PQ-Scout over
the pcaps those experiments saved in data/, compares each answer with the
ground truth fixed when the capture was made, and prints PASS/FAIL.

Run from the project folder:   python tests/verify_all.py
Report also written to:        results/verify_report.txt
"""
import io, json, os, sys, contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

with contextlib.redirect_stderr(io.StringIO()):          # hide scapy's libpcap warning
    from pqscout.pcap_reader import analyse_pcap
    from pqscout.hndl_score import score_observation
    from pqscout.tls_constants import NAMED_GROUPS
    import robustness_multiflow, stress_experiment, pq_hybrid_experiment
    import test_registry_conformance

lines = []
def say(s=""):
    print(s); lines.append(s)

results = {}

# 1. Constructed-ground-truth batch -----------------------------------------
gt = json.load(open("data/batch/ground_truth.json"))
tls_ok = tls_n = neg_ok = neg_n = 0
fails = []
for case in gt:
    if case.get("packets", 1) == 0:
        continue                                        # the 2 excluded 3DES cases
    obs = [o for o in analyse_pcap(case["pcap"]) if o.selected_cipher or o.negotiated_version]
    if case["kind"] == "tls":
        tls_n += 1
        t = case["truth"]
        o = obs[0] if obs else None
        got = o and dict(version=o.negotiated_version, cipher=o.selected_cipher,
                         kex=o.key_exchange, group=o.named_group)
        if got == t:
            tls_ok += 1
        else:
            fails.append(case["name"])
    else:
        neg_n += 1
        neg_ok += (not obs)
ok1 = tls_ok == tls_n and neg_ok == neg_n
results["1 Batch (41 cases)"] = ok1
say("1. Constructed-ground-truth batch")
say(f"   TLS cases fully correct: {tls_ok}/{tls_n}   negative controls ignored: {neg_ok}/{neg_n}"
    + (f"   FAILED: {fails}" if fails else ""))

# 2. Multi-flow ---------------------------------------------------------------
found = {o.dport: o for o in analyse_pcap("data/multiflow.pcap")}
good = 0
for port, _, ver, cipher, group in robustness_multiflow.CONFIGS:
    o = found.get(port)
    good += bool(o and o.selected_cipher == cipher and o.negotiated_version == ver
                 and o.named_group == group)
n2 = len(robustness_multiflow.CONFIGS)
results["2 Multi-flow"] = good == n2
say(f"\n2. Multi-flow concurrency\n   connections correctly separated and attributed: {good}/{n2}")

# 3. Stress (saved damaged captures) -----------------------------------------
EXPECT = {"baseline": "CORRECT", "fragmented": "CORRECT", "reordered": "CORRECT",
          "duplicated": "CORRECT", "lossy": "SAFE_MISS", "midsession": "SAFE_MISS"}
say("\n3. Adversarial / degraded traffic   (expected after the fix: loss and late capture -> SAFE_MISS)")
wrong = mism = 0
for case in stress_experiment.BASE_CASES:
    row = []
    for cond, exp in EXPECT.items():
        path = f"data/stress/{case['name']}__{cond}.pcap"
        try:
            outcome, _ = stress_experiment.classify(analyse_pcap(path), case["truth"])
        except Exception as e:
            outcome = "CRASH"
        wrong += outcome in ("WRONG", "CRASH")
        mism += outcome != exp
        row.append(f"{cond}={outcome}")
    say(f"   {case['name']:<20} " + "  ".join(row))
results["3 Stress"] = wrong == 0 and mism == 0
say(f"   confident-wrong or crash: {wrong}   unexpected outcomes: {mism}")

# 4. Nmap baseline (passive pcaps vs the Nmap sets recorded at run time) ------
nm = json.load(open("results/nmap_baseline.json"))["rows"]
cons = 0
say("\n4. Nmap baseline")
for r in nm:
    o = analyse_pcap(f"data/nmap_baseline/{r['case']}.pcap")
    c = o[0].selected_cipher if o else None
    inside = c in r["nmap_ciphers_found"]
    cons += inside
    say(f"   {r['case']:<16} PQ-Scout saw {c}  -> in Nmap's set of {len(r['nmap_ciphers_found'])}: {inside}")
results["4 Nmap baseline"] = cons == len(nm)

# 5. Post-quantum hybrid -------------------------------------------------------
say("\n5. Post-quantum hybrid (Go-generated handshakes)")
pq_ok = 0
for name, _, _, _, exp_group, exp_band in pq_hybrid_experiment.CASES:
    o = analyse_pcap(f"data/pq_hybrid/{name}.pcap")
    o = o[0] if o else None
    score, band, _ = score_observation(o) if o else (None, None, None)
    ok = o is not None and o.named_group == exp_group and band == exp_band
    pq_ok += ok
    say(f"   {name:<26} group={o.named_group if o else None:<15} score={score} band={band}  "
        f"{'PASS' if ok else 'FAIL'}")
results["5 PQ hybrid"] = pq_ok == len(pq_hybrid_experiment.CASES)

# 6. Registry conformance (stored IANA snapshot; no network needed) ----------
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    f6 = test_registry_conformance.check(test_registry_conformance.IANA_SNAPSHOT, "snapshot")
results["6 IANA registry"] = f6 == 0
say(f"\n6. Registry conformance\n   post-quantum codepoints matching IANA snapshot: "
    f"{len(test_registry_conformance.IANA_SNAPSHOT) - f6}/{len(test_registry_conformance.IANA_SNAPSHOT)}")

# Summary ----------------------------------------------------------------------
say("\n" + "=" * 60)
for k, v in results.items():
    say(f"  {'PASS' if v else 'FAIL'}   {k}")
say("=" * 60)
say(f"  {sum(results.values())}/{len(results)} experiments reproduce from saved captures")
os.makedirs("results", exist_ok=True)
open("results/verify_report.txt", "w", encoding="utf-8").write("\n".join(lines) + "\n")
sys.exit(0 if all(results.values()) else 1)
