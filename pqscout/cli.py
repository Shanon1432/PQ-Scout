"""PQ-Scout command line interface."""
import argparse, json, sys, glob
from .pcap_reader import analyse_pcap
from .cbom import build_cbom


def main():
    ap = argparse.ArgumentParser(prog="pqscout",
        description="Passive cryptographic discovery and HNDL risk prioritisation")
    ap.add_argument("pcaps", nargs="+", help="pcap file(s) to analyse")
    ap.add_argument("-o", "--out", help="write CBOM JSON to this path")
    args = ap.parse_args()

    observations = []
    for pattern in args.pcaps:
        for path in sorted(glob.glob(pattern)) or [pattern]:
            observations.extend(analyse_pcap(path))

    if not observations:
        print("No TLS handshakes found.", file=sys.stderr)
        return 1

    bom, findings = build_cbom(observations)

    print(f"\n  PQ-Scout  --  {len(findings)} asset(s), ranked by HNDL exposure\n")
    print(f"  {'SCORE':>6}  {'BAND':<9} {'ASSET':<22} {'TLS':<8} {'KEX':<7} {'GROUP':<16} CIPHER")
    print("  " + "-" * 108)
    for f in findings:
        o = f["obs"]
        print(f"  {f['score']:>6}  {f['band']:<9} {o.asset_id():<22} "
              f"{str(o.negotiated_version):<8} {str(o.key_exchange):<7} "
              f"{str(o.named_group):<16} {o.selected_cipher}")
    print()
    for f in findings[:3]:
        print(f"  * {f['asset']} [{f['band']}] -- {f['rationale']}")

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(bom, fh, indent=2)
        print(f"\n  CBOM written to {args.out}\n")
    return 0
