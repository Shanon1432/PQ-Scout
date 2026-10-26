"""Evaluate PQ-Scout against constructed ground truth.

Computes:
  1. Handshake DETECTION metrics (TP/FP/FN/TN) using positive TLS cases
     and non-TLS negative controls.
  2. FIELD IDENTIFICATION accuracy for version, cipher suite, key exchange
     and named group, among correctly detected handshakes.
  3. Macro-averaged precision / recall / F1 for cipher-suite classification.
"""
import json, os, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pqscout import analyse_pcap

GT = "data/batch/ground_truth.json"
FIELDS = ["version", "cipher", "kex", "group"]


def predict(pcap):
    """Return the single best observation from a pcap, or None."""
    try:
        obs = analyse_pcap(pcap)
    except Exception:
        return None
    obs = [o for o in obs if o.selected_cipher or o.negotiated_version]
    if not obs:
        return None
    o = obs[0]
    return dict(version=o.negotiated_version, cipher=o.selected_cipher,
                kex=o.key_exchange, group=o.named_group)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def main():
    cases = json.load(open(GT))
    excluded, rows = [], []

    for c in cases:
        if not c.get("ok") or not os.path.exists(c.get("pcap", "")):
            excluded.append((c["name"], "capture failed")); continue
        if c["kind"] == "tls" and c.get("packets", 0) == 0:
            excluded.append((c["name"], "configuration not negotiable in test environment"))
            continue
        rows.append((c, predict(c["pcap"])))

    # ---------------- 1. detection ----------------
    tp = sum(1 for c, p in rows if c["kind"] == "tls" and p)
    fn = sum(1 for c, p in rows if c["kind"] == "tls" and not p)
    fp = sum(1 for c, p in rows if c["kind"] != "tls" and p)
    tn = sum(1 for c, p in rows if c["kind"] != "tls" and not p)
    dp, dr, df = prf(tp, fp, fn)

    # ---------------- 2. field identification ----------------
    field_stats = {f: {"correct": 0, "total": 0, "errors": []} for f in FIELDS}
    for c, p in rows:
        if c["kind"] != "tls" or not p:
            continue
        for f in FIELDS:
            exp, got = c["truth"][f], p[f]
            field_stats[f]["total"] += 1
            if exp == got:
                field_stats[f]["correct"] += 1
            else:
                field_stats[f]["errors"].append((c["name"], exp, got))

    # ---------------- 3. cipher-suite macro P/R/F1 ----------------
    cls = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for c, p in rows:
        if c["kind"] != "tls" or not p:
            continue
        exp, got = c["truth"]["cipher"], p["cipher"]
        if exp == got:
            cls[exp]["tp"] += 1
        else:
            cls[exp]["fn"] += 1
            cls[got]["fp"] += 1
    macro = [prf(v["tp"], v["fp"], v["fn"]) for v in cls.values()]
    mp = sum(m[0] for m in macro) / len(macro) if macro else 0
    mr = sum(m[1] for m in macro) / len(macro) if macro else 0
    mf = sum(m[2] for m in macro) / len(macro) if macro else 0

    # ---------------- report ----------------
    W = 74
    print("\n" + "=" * W)
    print("  PQ-Scout — Evaluation against constructed ground truth".ljust(W))
    print("=" * W)
    print(f"  Cases executed        : {len(cases)}")
    print(f"  Cases evaluated       : {len(rows)}  "
          f"({sum(1 for c,_ in rows if c['kind']=='tls')} TLS, "
          f"{sum(1 for c,_ in rows if c['kind']!='tls')} negative controls)")
    print(f"  Excluded              : {len(excluded)}")
    for n, why in excluded:
        print(f"       - {n}: {why}")

    print("\n  1. HANDSHAKE DETECTION")
    print(f"     TP={tp}  FP={fp}  FN={fn}  TN={tn}")
    print(f"     Precision {dp:.3f}   Recall {dr:.3f}   F1 {df:.3f}")

    print("\n  2. FIELD IDENTIFICATION ACCURACY (detected handshakes)")
    print(f"     {'Field':<12}{'Correct':>10}{'Total':>8}{'Accuracy':>11}")
    for f in FIELDS:
        s = field_stats[f]
        acc = s["correct"] / s["total"] if s["total"] else 0
        print(f"     {f:<12}{s['correct']:>10}{s['total']:>8}{acc:>10.1%}")

    print("\n  3. CIPHER-SUITE CLASSIFICATION (macro-averaged over "
          f"{len(cls)} classes)")
    print(f"     Precision {mp:.3f}   Recall {mr:.3f}   F1 {mf:.3f}")

    errs = [(f, e) for f in FIELDS for e in field_stats[f]["errors"]]
    print(f"\n  4. MISCLASSIFICATIONS: {len(errs)}")
    for f, (name, exp, got) in errs[:12]:
        print(f"     [{f}] {name}: expected {exp!r}, got {got!r}")
    print("=" * W + "\n")

    os.makedirs("results", exist_ok=True)
    json.dump({
        "cases_executed": len(cases), "cases_evaluated": len(rows),
        "excluded": excluded,
        "detection": {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                      "precision": round(dp, 4), "recall": round(dr, 4), "f1": round(df, 4)},
        "field_accuracy": {f: {"correct": field_stats[f]["correct"],
                               "total": field_stats[f]["total"],
                               "accuracy": round(field_stats[f]["correct"] /
                                                 field_stats[f]["total"], 4)
                               if field_stats[f]["total"] else None,
                               "errors": field_stats[f]["errors"]} for f in FIELDS},
        "cipher_macro": {"precision": round(mp, 4), "recall": round(mr, 4),
                         "f1": round(mf, 4), "classes": len(cls)},
    }, open("results/metrics.json", "w"), indent=2)
    print("  Metrics written to results/metrics.json\n")


if __name__ == "__main__":
    main()
