"""Check every number quoted in the project report against the results files.

Each line below is a figure that appears in the report (section given in
brackets). The script recomputes or re-reads it from the evidence and
prints PASS or FAIL, so the report can be checked in one command.

Run from the project folder:   python tests/check_report_numbers.py
"""
import io, json, os, sys, contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT); sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tests"))
with contextlib.redirect_stderr(io.StringIO()):
    from pqscout.pcap_reader import analyse_pcap
    from pqscout.cbom import build_cbom
    import test_registry_conformance as reg

J = lambda p: json.load(open(p))
m = J("results/metrics.json")
mf = J("results/multiflow.json")
sa, sb = J("results/stress_metrics.json")["summary"], J("results/stress_metrics_before_fix.json")["summary"]
nm = J("results/nmap_baseline.json")["rows"]
pq = {r["case"]: r for r in J("results/pq_hybrid.json")["rows"]}
_, findings = build_cbom(analyse_pcap("data/multiflow.pcap"))
scores = sorted(f["score"] for f in findings)
with contextlib.redirect_stdout(io.StringIO()):
    reg_fail_now = reg.check(reg.IANA_SNAPSHOT, "now")
before_txt = open("results/registry_conformance_before_fix.txt").read()
d = m["detection"]

checks = [
    ("41 cases executed, 39 evaluated, 2 excluded (3.3, Table 2)",
     (m["cases_executed"], m["cases_evaluated"], len(m["excluded"])) == (41, 39, 2)),
    ("TP 34, FP 0, FN 0, TN 5 (Abstract, Table 7)", (d["tp"], d["fp"], d["fn"], d["tn"]) == (34, 0, 0, 5)),
    ("Precision / recall / F1 = 1.000 (Abstract, Table 7)", (d["precision"], d["recall"], d["f1"]) == (1.0, 1.0, 1.0)),
    ("Every field correct in 34/34 TLS cases (Table 7)",
     all(v["correct"] == v["total"] == 34 for v in m["field_accuracy"].values())),
    ("Cipher-suite macro-F1 1.000 over 21 classes (3.3, Table 7)",
     (m["cipher_macro"]["f1"], m["cipher_macro"]["classes"]) == (1.0, 21)),
    ("Multi-flow: 8 connections, 228 packets, 8/8 attributed (3.4, Table 7)",
     (mf["connections"], mf["packets"], mf["correct"]) == (8, 228, 8)),
    ("Before fix: targeted loss WRONG in 3/3 (6.2, Table 5, Figure 2)", sb["lossy"]["WRONG"] == 3),
    ("After fix: 0 WRONG and 0 CRASH in every condition (Table 7)",
     all(v["WRONG"] == 0 and v["CRASH"] == 0 for v in sa.values())),
    ("After fix: loss and late capture give safe misses 3/3 each (Table 7)",
     sa["lossy"]["SAFE_MISS"] == 3 and sa["midsession"]["SAFE_MISS"] == 3),
    ("Fragmented / reordered / duplicated all correct (Figure 2)",
     all(sa[c]["CORRECT"] == 3 for c in ("fragmented", "reordered", "duplicated"))),
    ("Nmap listed 20, 20 and 3 suites (6.5)", [len(r["nmap_ciphers_found"]) for r in nm] == [20, 20, 3]),
    ("PQ-Scout's suite was in Nmap's list 3/3 (Abstract, 6.5)", all(r["consistent_with_nmap"] for r in nm)),
    ("X25519MLKEM768 scored 0.0 LOW (Abstract, Table 7)",
     (pq["pq_hybrid_x25519mlkem768"]["score"], pq["pq_hybrid_x25519mlkem768"]["observed_band"]) == (0.0, "LOW")),
    ("Classical x25519 and P-256 scored 58.5 HIGH (Table 7)",
     all((pq[c]["score"], pq[c]["observed_band"]) == (58.5, "HIGH") for c in ("classical_x25519", "classical_p256_via_hrr"))),
    ("Go tests correct 3/3; HelloRetryRequest seen in P-256 case (Table 7, 4.6)",
     all(r["correct"] for r in pq.values()) and pq["classical_p256_via_hrr"]["hello_retry"]),
    ("IANA: 12/12 match now (Table 5, Table 7)", reg_fail_now == 0),
    ("IANA: 7 failures before the fix (Table 5)", "7 FAILURE(S)" in before_txt),
    ("Classical multi-flow scores range 58.5 to 65.0 (6.4)", (min(scores), max(scores)) == (58.5, 65.0)),
    ("No multi-flow asset reaches CRITICAL >= 70 (6.4)", max(scores) < 70),
    ("Worked example: ECDHE on port 636 = 85.5, RSA on 443 = 60.0 (6.4)",
     round(0.90 * 0.95 * 100, 1) == 85.5 and round(1.00 * 0.60 * 100, 1) == 60.0),
]

passed = 0
for text, ok in checks:
    passed += bool(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {text}")
print(f"\n  {passed}/{len(checks)} report figures match the evidence")
print("  (CycloneDX schema claim: run  python tests/validate_cbom.py)")
sys.exit(0 if passed == len(checks) else 1)
