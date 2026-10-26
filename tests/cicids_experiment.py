"""Independent-data test: PQ-Scout on a public capture (CIC-IDS2017).

Step 1 (tests/cicids_prefilter.py) cuts the multi-gigabyte capture down to
the opening packets of TLS connections. This script then:

  1. runs PQ-Scout on those files (per-connection observations, HNDL scores,
     CycloneDX CBOM), and
  2. if a tshark export of the ORIGINAL full capture is given, compares
     PQ-Scout's answer for every connection with Wireshark's (tshark's)
     answer: negotiated TLS version, selected cipher suite, and, for TLS 1.3,
     the key-exchange group.

There is no ground truth for public traffic, so the comparison measures
agreement with an independent, widely used dissector, not accuracy.

Usage:
    python tests/cicids_experiment.py <prefilter_dir> [--tshark tshark.tsv]
           [--out results/cicids2017.json] [--cbom results/cicids2017_cbom.json]

The tshark export is made with (one line):
    tshark -r <full.pcap> -n -Y "tls.handshake.type==1 || tls.handshake.type==2"
      -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=;
      -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
      -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite
      -e tls.handshake.extensions.supported_version
      -e tls.handshake.extensions_key_share_group
      -e tls.handshake.extensions_server_name  > tshark.tsv
"""
import argparse, collections, contextlib, glob, io, json, os, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
with contextlib.redirect_stderr(io.StringIO()):
    from pqscout.pcap_reader import analyse_pcap
    from pqscout.cbom import build_cbom
    from pqscout.tls_constants import CIPHER_SUITES, TLS_VERSIONS, NAMED_GROUPS

CIPHER_CODE = {v[0]: k for k, v in CIPHER_SUITES.items()}
VERSION_CODE = {v: k for k, v in TLS_VERSIONS.items()}
GROUP_CODE = {v: k for k, v in NAMED_GROUPS.items()}


def _code(name, table):
    """PQ-Scout reports names, or '0x....' for codepoints it does not know."""
    if name is None:
        return None
    if name in table:
        return table[name]
    if isinstance(name, str) and name.startswith("0x"):
        return int(name, 16)
    return None


def _num(v):
    v = v.strip()
    return int(v, 0) if v else None


def load_tshark(path):
    """Per connection (client ip, client port, server ip, server port):
    the values Wireshark decoded from the ClientHello and the final ServerHello."""
    conns = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        col = {h: i for i, h in enumerate(header)}
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) < len(header):
                f += [""] * (len(header) - len(f))
            g = lambda name: f[col[name]]
            types = [t for t in g("tls.handshake.type").split(";") if t]
            src, sport, dst, dport = g("ip.src"), g("tcp.srcport"), g("ip.dst"), g("tcp.dstport")
            if not (src and sport and dst and dport):
                continue                                   # IPv6 or odd frame
            if "1" in types:
                key = (src, int(sport), dst, int(dport))
                c = conns.setdefault(key, {})
                if "client_hello_frame" not in c:
                    c["client_hello_frame"] = int(g("frame.number"))
                    c["sni"] = g("tls.handshake.extensions_server_name").split(";")[0]
            if "2" in types:
                key = (dst, int(dport), src, int(sport))
                c = conns.setdefault(key, {})
                ciphers = [x for x in g("tls.handshake.ciphersuite").split(";") if x]
                vers = [x for x in g("tls.handshake.version").split(";") if x]
                sv = [x for x in g("tls.handshake.extensions.supported_version").split(";") if x]
                ks = [x for x in g("tls.handshake.extensions_key_share_group").split(";") if x]
                # later ServerHellos overwrite earlier ones (HelloRetryRequest case)
                c["cipher"] = _num(ciphers[-1]) if ciphers else None
                c["version"] = _num(sv[-1]) if sv else (_num(vers[-1]) if vers else None)
                c["group"] = _num(ks[-1]) if ks else None
                c["server_hello_frame"] = int(g("frame.number"))
    return conns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prefilter_dir")
    ap.add_argument("--tshark")
    ap.add_argument("--out", default="results/cicids2017.json")
    ap.add_argument("--cbom", default="results/cicids2017_cbom.json")
    a = ap.parse_args()

    t0 = time.time()
    observations = []
    parts = sorted(glob.glob(os.path.join(a.prefilter_dir, "tls_part*.pcap")))
    for i, p in enumerate(parts, 1):
        with contextlib.redirect_stderr(io.StringIO()):
            observations.extend(analyse_pcap(p))
        print(f"  [{i}/{len(parts)}] {os.path.basename(p)}: {len(observations):,} handshakes so far",
              flush=True)
    analyse_s = round(time.time() - t0, 1)

    bom, findings = build_cbom(observations)
    with open(a.cbom, "w") as fh:
        json.dump(bom, fh, indent=1)

    # ---- what PQ-Scout found -------------------------------------------
    with_server = [o for o in observations if o.selected_cipher]
    by_conn = {(o.src, o.sport, o.dst, o.dport): o for o in observations}
    count = lambda it: dict(collections.Counter(it).most_common())
    band_conn = count(f["band"] for f in findings)
    # one row per server asset (ip:port), keeping its highest-scoring connection
    assets = {}
    for f in findings:                      # findings are sorted high -> low
        assets.setdefault(f["asset"], f)
    unknown_suites = count(o.selected_cipher for o in with_server
                           if o.selected_cipher.startswith("0x"))
    summary = {
        "dataset": "CIC-IDS2017 (Sharafaldin, Lashkari & Ghorbani, 2018)",
        "prefilter": json.load(open(os.path.join(a.prefilter_dir, "prefilter_summary.json"))),
        "pqscout_seconds": analyse_s,
        "tls_handshakes_observed": len(observations),
        "with_server_hello": len(with_server),
        "incomplete_captures": sum(1 for o in observations if o.incomplete),
        "unique_server_assets": len(assets),
        "tls_versions": count(str(o.negotiated_version) for o in with_server),
        "key_exchange": count(str(o.key_exchange) for o in with_server),
        "selected_cipher_top10": dict(list(count(o.selected_cipher for o in with_server).items())[:10]),
        "suites_not_in_pqscout_table": unknown_suites,
        "post_quantum_groups_seen": sum(1 for o in observations if o.named_group and (
            "MLKEM" in o.named_group or "Kyber" in o.named_group)),
        "hndl_band_per_connection": band_conn,
        "hndl_band_per_asset": count(f["band"] for f in assets.values()),
        "top_assets": [{"asset": f["asset"], "server_name": f["obs"].server_name,
                        "score": f["score"], "band": f["band"],
                        "version": f["obs"].negotiated_version,
                        "cipher": f["obs"].selected_cipher}
                       for f in list(assets.values())[:15]],
    }

    # ---- cross-check with Wireshark -------------------------------------
    if a.tshark:
        ts = load_tshark(a.tshark)
        ts_full = {k: v for k, v in ts.items() if "client_hello_frame" in v and "cipher" in v}
        both = [k for k in ts_full if k in by_conn and by_conn[k].selected_cipher]
        fields = {"version": [0, 0], "cipher": [0, 0], "group_tls13": [0, 0]}
        disagreements = []
        for k in both:
            o, t = by_conn[k], ts_full[k]
            checks = [("version", _code(o.negotiated_version, VERSION_CODE), t["version"]),
                      ("cipher", _code(o.selected_cipher, CIPHER_CODE), t["cipher"])]
            if t["version"] == 0x0304:
                checks.append(("group_tls13", _code(o.named_group, GROUP_CODE), t["group"]))
            for name, mine, theirs in checks:
                fields[name][1] += 1
                if mine == theirs:
                    fields[name][0] += 1
                else:
                    disagreements.append({
                        "connection": f"{k[0]}:{k[1]} -> {k[2]}:{k[3]}", "field": name,
                        "pqscout": None if mine is None else f"0x{mine:04x}",
                        "wireshark": None if theirs is None else f"0x{theirs:04x}",
                        "frame": t.get("server_hello_frame")})
        summary["wireshark_cross_check"] = {
            "tshark_connections_with_client_and_server_hello": len(ts_full),
            "pqscout_found_same_connection": len(both),
            "missed_by_pqscout": len([k for k in ts_full if k not in by_conn or not by_conn[k].selected_cipher]),
            "pqscout_only": len([k for k, o in by_conn.items() if o.selected_cipher and k not in ts_full]),
            "agreement": {n: {"agree": v[0], "compared": v[1],
                              "rate": round(v[0] / v[1], 4) if v[1] else None}
                          for n, v in fields.items()},
            "disagreement_count_by_field": count(d["field"] for d in disagreements),
            # blank = PQ-Scout gave no value (a safe miss); different = PQ-Scout
            # gave a value that differs from Wireshark's (a confident error)
            "disagreement_kind": count(f'{d["field"]}:{"blank" if d["pqscout"] is None else "different"}'
                                       for d in disagreements),
            "disagreement_examples": disagreements[:25],
        }
        missed = [k for k in ts_full if k not in by_conn or not by_conn[k].selected_cipher]
        summary["wireshark_cross_check"]["missed_examples"] = [
            {"connection": f"{k[0]}:{k[1]} -> {k[2]}:{k[3]}",
             "client_hello_frame": ts_full[k]["client_hello_frame"],
             "pqscout_saw_connection": k in by_conn,
             "pqscout_incomplete": by_conn[k].incomplete if k in by_conn else None}
            for k in missed[:25]]

    with open(a.out, "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps({k: v for k, v in summary.items() if k not in ("top_assets", "prefilter")}, indent=2))
    print(f"\n  results -> {a.out}\n  CBOM    -> {a.cbom}")


if __name__ == "__main__":
    main()
