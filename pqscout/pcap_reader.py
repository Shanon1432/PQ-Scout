"""Read pcap files, reassemble TCP streams, and extract TLS handshakes."""
from collections import defaultdict
from struct import error as struct_error
from scapy.all import rdpcap, TCP, IP

# RFC 8446 s4.1.3 / RFC 9846: a HelloRetryRequest is sent as a ServerHello
# whose random field is this fixed value (SHA-256 of "HelloRetryRequest").
HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
from .tls_parser import (
    HandshakeObservation, iter_handshake_messages,
    parse_client_hello, parse_server_hello,
)


def _streams(packets):
    """Group TCP payloads into directional streams keyed by connection."""
    flows = defaultdict(lambda: defaultdict(list))
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        # canonical connection key (lower endpoint first) so both
        # directions land in the same flow
        a = (ip.src, tcp.sport)
        b = (ip.dst, tcp.dport)
        key = (a, b) if a < b else (b, a)
        flows[key][(ip.src, tcp.sport, ip.dst, tcp.dport)].append(
            (tcp.seq, payload))
    return flows


def _reassemble(chunks):
    """Order by sequence number, drop retransmissions, and stop at the
    first genuine gap in the sequence space rather than silently
    concatenating non-contiguous bytes.

    Without this, a single lost segment shifts every byte after the gap
    into the wrong field -- the parser then reads a real-looking but
    *wrong* length/cipher-suite/group value instead of failing safe.
    Adversarial testing (tests/stress_experiment.py, 'lossy' condition)
    found this: 3/3 cases produced a confidently incorrect cipher suite
    under a single-packet loss before this fix. Truncating at the gap
    turns that into an honest "incomplete" result instead.
    """
    chunks = sorted(chunks, key=lambda c: c[0])
    seen, data = set(), b""
    expected = None
    gap = False
    for seq, payload in chunks:
        if seq in seen:
            continue
        seen.add(seq)
        if expected is not None and seq < expected:
            # Overlapping retransmission: the sender re-sent bytes we already
            # have, possibly with a different segment size. Keep only the new
            # bytes. The original version treated this as a gap; on
            # CIC-IDS2017 that lost 6 ClientHellos that had been re-sent in
            # differently sized pieces.
            if seq + len(payload) <= expected:
                continue
            payload = payload[expected - seq:]
            seq = expected
        if expected is not None and seq != expected:
            gap = True
            break                      # stop reassembling at the gap
        data += payload
        expected = seq + len(payload)
    return data, gap


def analyse_pcap(path):
    """Return a list of HandshakeObservation, one per TLS connection found."""
    packets = rdpcap(path)
    results = []

    for conn, directions in _streams(packets).items():
        obs = HandshakeObservation()
        saw_client = saw_server = False

        try:
            for (src, sport, dst, dport), chunks in directions.items():
                data, gap = _reassemble(chunks)
                if gap:
                    obs.incomplete = True

                for msg_type, body in iter_handshake_messages(data):
                    if msg_type == 1 and not saw_client:   # first ClientHello
                        # (a second ClientHello only follows a
                        # HelloRetryRequest; re-parsing it would just
                        # duplicate the offered cipher/group lists)
                        obs.src, obs.dst, obs.dport, obs.sport = src, dst, dport, sport
                        parse_client_hello(body, obs)
                        saw_client = True
                    elif msg_type == 2:                    # ServerHello / HRR
                        if body[2:34] == HRR_RANDOM:
                            obs.hello_retry = True         # the real ServerHello
                        parse_server_hello(body, obs)      # follows and overwrites
                        saw_server = True
                        server_dir = (src, sport, dst, dport)
        except (IndexError, struct_error):
            # malformed/truncated handshake bytes (e.g. damage landed on a
            # length field) must not take the rest of the pcap down with
            # it -- report what little is known, flagged incomplete.
            obs.incomplete = True

        if saw_server and not saw_client:
            # Only the server side was readable: name the connection from the
            # direction that carried the ServerHello, instead of leaving the
            # asset blank (":0") as the original version did.
            s_src, s_sport, s_dst, s_dport = server_dir
            obs.src, obs.sport, obs.dst, obs.dport = s_dst, s_dport, s_src, s_sport
        if saw_client or saw_server:
            if not obs.negotiated_version and not obs.incomplete:
                # ClientHello's legacy_version is a safe stand-in for the
                # negotiated version ONLY when the record layer tells us
                # nothing more specific (true for TLS 1.0-1.2). For TLS
                # 1.3 the real version lives in the ServerHello's
                # supported_versions extension -- if reassembly was
                # incomplete and we never saw that extension, guessing
                # "TLS 1.2" from the legacy field would be actively wrong
                # (every TLS 1.3 ClientHello also carries legacy_version
                # TLS 1.2 for backwards compatibility). Stay silent
                # instead of reporting a plausible-looking wrong answer.
                obs.negotiated_version = obs.legacy_version
            results.append(obs)
    return results
