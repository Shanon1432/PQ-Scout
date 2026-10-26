"""Adversarial / degraded-condition stress testing for PQ-Scout.

Real networks are not the clean, single-handshake, loopback conditions the
first 41-case batch used. This harness takes known-good captures (ground
truth fixed at generation time, same discipline as batch_experiment.py) and
deliberately damages them in ways a passive sniffer really encounters:

  fragmented   - handshake bytes split into many small TCP segments
  reordered    - packets delivered out of order (sniffer / multi-path jitter)
  duplicated   - retransmitted packets duplicated in the capture
  lossy        - a packet genuinely missing (sniffer drop / network loss)
  midsession   - capture starts after the connection is already underway
  nonstandard  - server listening on a high, non-443 port (not a corruption;
                 a coverage check folded into the base-case ports)

For every (case, condition) we classify the outcome against the known
ground truth as:

  CORRECT    - every ground-truth field matches
  SAFE_MISS  - tool reports nothing / incomplete rather than guessing
  WRONG      - tool reports a confident but incorrect answer (the
               dangerous outcome -- worse than reporting nothing)
  CRASH      - analyse_pcap raised an unhandled exception

This is written to be run twice: once against the as-delivered pcap_reader
(to see what actually happens under damage), and again after the hardening
patch described in results/stress_findings.md, so the before/after is
on the record rather than asserted.
"""
import json, os, random, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import AsyncSniffer, rdpcap, wrpcap, IP, TCP
from pqscout.pcap_reader import analyse_pcap

random.seed(1337)  # deterministic damage patterns -- reproducible, not cherry-picked

DATA = "data/stress"
RESULTS = "results"
os.makedirs(DATA, exist_ok=True)
os.makedirs(RESULTS, exist_ok=True)


# ---------------------------------------------------------------------------
# 1. Base cases: known ground truth, generated the same way as the 41-case
#    batch (configure server first, so we know the right answer before the
#    tool ever sees the traffic). Ports are deliberately non-standard.
# ---------------------------------------------------------------------------
BASE_CASES = [
    # name, port, server openssl flags, ground truth
    dict(name="base_tls13_x25519", port=18443,
         server=["-tls1_3", "-groups", "X25519"],
         truth=dict(negotiated_version="TLS 1.3", key_exchange="ECDHE", named_group="x25519")),
    dict(name="base_tls12_ecdhe", port=28443,
         server=["-tls1_2", "-cipher", "ECDHE-RSA-AES256-GCM-SHA384"],
         truth=dict(negotiated_version="TLS 1.2", key_exchange="ECDHE",
                     selected_cipher="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")),
    dict(name="base_tls12_rsa", port=38443,
         server=["-tls1_2", "-cipher", "AES128-SHA"],
         truth=dict(negotiated_version="TLS 1.2", key_exchange="RSA",
                     selected_cipher="TLS_RSA_WITH_AES_128_CBC_SHA")),
]


def _capture_case(case):
    port = case["port"]
    sniffer = AsyncSniffer(iface="lo", store=True)
    sniffer.start(); time.sleep(0.5)
    srv = subprocess.Popen(
        ["openssl", "s_server", "-accept", str(port), "-cert", "data/cert.pem",
         "-key", "data/key.pem", "-quiet", "-naccept", "1"] + case["server"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    time.sleep(1.0)
    subprocess.run(
        ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "pqscout-lab.local"]
        + case["server"],
        input=b"Q\n", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    time.sleep(0.6)
    pkts = sniffer.stop()
    srv.terminate()
    path = f"{DATA}/{case['name']}.pcap"
    wrpcap(path, pkts)
    return path, pkts


# ---------------------------------------------------------------------------
# 2. Damage functions -- each takes the base packet list and returns a new,
#    deliberately degraded packet list.
# ---------------------------------------------------------------------------
def _data_packet_indices(pkts):
    return [i for i, p in enumerate(pkts)
            if p.haslayer(TCP) and p.haslayer(IP) and bytes(p[TCP].payload)]


def damage_fragmented(pkts, chunk_size=8):
    """Re-split every data-carrying packet's TCP payload into many tiny
    segments, each its own packet with the correct incrementing seq number.
    Simulates a low-MTU path / aggressive segmentation."""
    out = []
    for p in pkts:
        if p.haslayer(TCP) and p.haslayer(IP) and bytes(p[TCP].payload):
            payload = bytes(p[TCP].payload)
            seq = p[TCP].seq
            for off in range(0, len(payload), chunk_size):
                piece = payload[off:off + chunk_size]
                clone = p.copy()
                clone[TCP].seq = seq + off
                clone[TCP].remove_payload()
                clone = clone / piece
                out.append(clone)
        else:
            out.append(p)
    return out


def damage_reordered(pkts):
    """Shuffle the order data packets appear in the capture. Reassembly
    sorts by TCP sequence number, so correctness should survive this if
    the tool is implemented properly."""
    idx = _data_packet_indices(pkts)
    shuffled = idx[:]
    random.shuffle(shuffled)
    out = list(pkts)
    for src_i, dst_i in zip(idx, shuffled):
        out[dst_i] = pkts[src_i]
    return out


def damage_duplicated(pkts):
    """Duplicate ~30% of data packets at random positions, simulating
    retransmissions a sniffer captures twice."""
    idx = _data_packet_indices(pkts)
    out = list(pkts)
    for i in idx:
        if random.random() < 0.3:
            out.insert(i, pkts[i])
    return out


def _reassemble_direction(pkts, sport):
    """Same reassembly rule as pcap_reader._streams, for one direction
    (identified by TCP source port), so we can locate exact byte offsets."""
    chunks = [(p[TCP].seq, bytes(p[TCP].payload)) for p in pkts
              if p.haslayer(TCP) and p.haslayer(IP) and p[TCP].sport == sport
              and bytes(p[TCP].payload)]
    if not chunks:
        return None, b""
    chunks.sort(key=lambda c: c[0])
    seen, data = set(), b""
    base_seq = chunks[0][0]
    for seq, payload in chunks:
        if seq in seen:
            continue
        seen.add(seq)
        data += payload
    return base_seq, data


def _locate_server_hello(server_stream):
    """Scan the server->client byte stream for the ServerHello handshake
    message. Returns (body_start_offset, body_end_offset) of the message
    body within the stream, or None if not found."""
    i, n = 0, len(server_stream)
    while i + 5 <= n:
        ctype = server_stream[i]
        if ctype != 22:
            break
        rec_len = int.from_bytes(server_stream[i + 3:i + 5], "big")
        rec_start = i + 5
        rec = server_stream[rec_start: rec_start + rec_len]
        i = rec_start + rec_len
        j = 0
        while j + 4 <= len(rec):
            msg_type = rec[j]
            msg_len = int.from_bytes(b"\x00" + rec[j + 1:j + 4], "big")
            body_start = rec_start + j + 4
            body_end = body_start + msg_len
            if msg_type == 2:                       # ServerHello
                return body_start, body_end
            j += 4 + msg_len
    return None


def _cipher_suite_seq_range(pkts, server_port):
    """Work out exactly which TCP sequence-number range in the server's
    stream carries the 2-byte selected-cipher-suite field, so damage can
    be targeted at the field actually being scored (not a blind guess)."""
    base_seq, stream = _reassemble_direction(pkts, server_port)
    loc = _locate_server_hello(stream)
    if base_seq is None or loc is None:
        return None
    body_start, _ = loc
    i = body_start + 2 + 32                         # version + random
    sid_len = stream[i]; i += 1 + sid_len            # session id
    cipher_offset = i                                # the 2 bytes we target
    return base_seq + cipher_offset, base_seq + cipher_offset + 2


def _server_hello_end_seq(pkts, server_port):
    base_seq, stream = _reassemble_direction(pkts, server_port)
    loc = _locate_server_hello(stream)
    if base_seq is None or loc is None:
        return None
    _, body_end = loc
    return base_seq + body_end


def damage_lossy(pkts, server_port):
    """Fragment finely, then drop precisely the segment(s) carrying the
    negotiated cipher-suite bytes in the ServerHello -- a loss that lands
    exactly on the field being scored, not an arbitrary 'middle' packet."""
    target = _cipher_suite_seq_range(pkts, server_port)
    frag = damage_fragmented(pkts, chunk_size=4)
    if target is None:
        return frag
    lo, hi = target
    out = []
    for p in frag:
        if (p.haslayer(TCP) and p.haslayer(IP) and p[TCP].sport == server_port
                and bytes(p[TCP].payload)):
            seq = p[TCP].seq
            seg_len = len(bytes(p[TCP].payload))
            if seq < hi and seq + seg_len > lo:      # overlaps the target bytes
                continue                              # drop this fragment
        out.append(p)
    return out


def damage_midsession(pkts, server_port):
    """Drop every packet (both directions) up to and including the one
    that completes the ServerHello -- simulates a sniffer that attached
    to the link well after the connection was already underway, missing
    the entire handshake's clear-text negotiation."""
    cutoff_seq = _server_hello_end_seq(pkts, server_port)
    if cutoff_seq is None:
        return pkts
    # find the capture index of the last packet whose bytes are needed to
    # reach cutoff_seq in the server direction, then drop up to that index
    last_idx = 0
    for i, p in enumerate(pkts):
        if (p.haslayer(TCP) and p.haslayer(IP) and p[TCP].sport == server_port
                and bytes(p[TCP].payload)):
            seq = p[TCP].seq
            seg_len = len(bytes(p[TCP].payload))
            if seq < cutoff_seq <= seq + seg_len:
                last_idx = i
    return pkts[last_idx + 1:]


CONDITIONS = {
    "baseline": lambda pkts, port: list(pkts),
    "fragmented": lambda pkts, port: damage_fragmented(pkts),
    "reordered": lambda pkts, port: damage_reordered(pkts),
    "duplicated": lambda pkts, port: damage_duplicated(pkts),
    "lossy": lambda pkts, port: damage_lossy(pkts, port),
    "midsession": lambda pkts, port: damage_midsession(pkts, port),
}


# ---------------------------------------------------------------------------
# 3. Classification
# ---------------------------------------------------------------------------
def classify(obs_list, truth):
    if not obs_list:
        return "SAFE_MISS", "no handshake observed"
    obs = obs_list[0]
    mismatches = []
    for field, expected in truth.items():
        got = getattr(obs, field, None)
        if got != expected:
            mismatches.append(f"{field}: expected {expected!r}, got {got!r}")
    if not mismatches:
        return "CORRECT", ""
    # distinguish "said nothing useful" from "said something wrong"
    all_none = all(getattr(obs, f, None) is None for f in truth)
    if all_none:
        return "SAFE_MISS", "; ".join(mismatches)
    return "WRONG", "; ".join(mismatches)


def run():
    # cert for the loopback server, if not already present
    if not os.path.exists("data/cert.pem"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                         "-keyout", "data/key.pem", "-out", "data/cert.pem",
                         "-days", "365", "-nodes", "-subj", "/CN=pqscout-lab.local"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    rows = []
    for case in BASE_CASES:
        path, base_pkts = _capture_case(case)
        print(f"[{case['name']}] captured {len(base_pkts)} packets on port {case['port']}")

        for cond_name, fn in CONDITIONS.items():
            damaged = fn(base_pkts, case["port"])
            dpath = f"{DATA}/{case['name']}__{cond_name}.pcap"
            wrpcap(dpath, damaged)

            try:
                obs_list = analyse_pcap(dpath)
                outcome, detail = classify(obs_list, case["truth"])
            except Exception as e:
                outcome, detail = "CRASH", f"{type(e).__name__}: {e}"

            rows.append(dict(case=case["name"], condition=cond_name,
                              packets=len(damaged), outcome=outcome, detail=detail))
            print(f"    {cond_name:<12} -> {outcome:<10} {detail}")

    summary = {}
    for r in rows:
        summary.setdefault(r["condition"], {"CORRECT": 0, "SAFE_MISS": 0, "WRONG": 0, "CRASH": 0})
        summary[r["condition"]][r["outcome"]] += 1

    out = dict(generated_cases=len(BASE_CASES), conditions=list(CONDITIONS),
               rows=rows, summary=summary)
    with open(f"{RESULTS}/stress_metrics.json", "w") as fh:
        json.dump(out, fh, indent=2)

    print("\n  Condition     CORRECT  SAFE_MISS  WRONG  CRASH")
    print("  " + "-" * 50)
    for cond, s in summary.items():
        print(f"  {cond:<12}  {s['CORRECT']:^7}  {s['SAFE_MISS']:^9}  {s['WRONG']:^5}  {s['CRASH']:^5}")
    print(f"\n  Written to {RESULTS}/stress_metrics.json")
    return out


if __name__ == "__main__":
    run()
