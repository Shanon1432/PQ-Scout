"""Cut a large public capture (e.g. CIC-IDS2017) down to its TLS handshakes.

A full CIC-IDS2017 day is several gigabytes, far too large to load into
Scapy. This script streams the file once, packet by packet, and keeps only
the opening packets of TCP connections whose first payload byte looks like
a TLS handshake record (0x16 0x03). Everything after the first few data
packets of each connection is dropped. Those opening packets carry the
cleartext handshake and may also hold a few encrypted application-data
records, which PQ-Scout never decrypts or analyses.

Output: one or more small classic-pcap files (CHUNK connections each) that
PQ-Scout can analyse, plus a JSON summary of what was kept.

Usage:
    python tests/cicids_prefilter.py <input.pcap> <output_dir> [--keep 8] [--chunk 2000]
"""
import argparse, json, os, struct, sys, time

ETH, LINUX_SLL, RAW = 1, 113, 101


def _l3_offset(linktype, pkt):
    """Return (offset of IPv4 header, or None) for the given link type."""
    if linktype == ETH:
        if len(pkt) < 14:
            return None
        off, etype = 14, struct.unpack_from("!H", pkt, 12)[0]
        while etype in (0x8100, 0x88A8) and len(pkt) >= off + 4:   # VLAN tags
            etype = struct.unpack_from("!H", pkt, off + 2)[0]
            off += 4
        return off if etype == 0x0800 else None
    if linktype == LINUX_SLL:
        if len(pkt) < 16:
            return None
        return 16 if struct.unpack_from("!H", pkt, 14)[0] == 0x0800 else None
    if linktype == RAW:
        return 0 if pkt and (pkt[0] >> 4) == 4 else None
    return None


def _pcap_records(f):
    gh = f.read(24)
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        sys.exit("Unrecognised capture format (expected pcap or pcapng)")
    linktype = struct.unpack(e + "I", gh[20:24])[0]
    hdr = struct.Struct(e + "IIII")

    def gen():
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            ts_s, ts_us, incl, orig = hdr.unpack(h)
            pkt = f.read(incl)
            if len(pkt) < incl:
                return
            yield ts_s, ts_us, pkt, orig
    return gen(), linktype


def _pcapng_records(f):
    """Minimal pcapng reader: Section Header, Interface Description and
    Enhanced/Simple Packet blocks. Assumes one interface link type."""
    shb = f.read(12)
    e = "<" if shb[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    blen = struct.unpack(e + "I", shb[4:8])[0]
    f.seek(blen)                                   # skip rest of first SHB
    linktypes, resol = [], []
    # read ahead until the first IDB to learn the link type
    pending = []
    while not linktypes:
        bh = f.read(8)
        btype, blen = struct.unpack(e + "II", bh)
        body = f.read(blen - 8)
        if btype == 1:
            linktypes.append(struct.unpack(e + "H", body[:2])[0])
            resol.append(_tsresol(body[8:-4], e))
        else:
            pending.append((btype, body))

    def gen():
        blocks = iter(pending)
        while True:
            nxt = next(blocks, None)
            if nxt is None:
                bh = f.read(8)
                if len(bh) < 8:
                    return
                btype, blen = struct.unpack(e + "II", bh)
                body = f.read(blen - 8)
                if len(body) < blen - 8:
                    return
            else:
                btype, body = nxt
            if btype == 6:                            # Enhanced Packet Block
                iface, th, tl, cap, orig = struct.unpack_from(e + "IIIII", body, 0)
                pkt = body[20:20 + cap]
                ticks = (th << 32) | tl
                per_s = resol[iface] if iface < len(resol) else 1_000_000
                yield ticks // per_s, (ticks % per_s) * 1_000_000 // per_s, pkt, orig
            elif btype == 3:                          # Simple Packet Block
                orig = struct.unpack_from(e + "I", body, 0)[0]
                yield 0, 0, body[4:4 + min(orig, len(body) - 8)], orig
            elif btype == 1:                          # further interfaces
                linktypes.append(struct.unpack(e + "H", body[:2])[0])
                resol.append(_tsresol(body[8:-4], e))
    return gen(), linktypes[0]


def _tsresol(opts, e):
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack_from(e + "HH", opts, i)
        if code == 0:
            break
        if code == 9 and ln >= 1:
            v = opts[i + 4]
            return 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
        i += 4 + ((ln + 3) & ~3)
    return 1_000_000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("outdir")
    ap.add_argument("--keep", type=int, default=8,
                    help="data packets kept per direction of each TLS connection")
    ap.add_argument("--chunk", type=int, default=2000,
                    help="TLS connections per output file")
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    f = open(a.pcap, "rb")
    first = f.read(4)
    f.seek(0)
    if first == b"\x0a\x0d\x0d\x0a":
        records, linktype = _pcapng_records(f)
    else:
        records, linktype = _pcap_records(f)
    # output files are always classic pcap (what PQ-Scout/Scapy reads fastest)
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype)
    rec_hdr = struct.Struct("<IIII")

    conns = {}          # canonical 4-tuple -> [state, chunk_id, {dir: kept}]
    #  state: 1 = TLS candidate, 0 = not TLS (ignore)
    writers = {}
    n_tls = total = ipv4_tcp = kept_pkts = 0
    t0 = time.time()

    def writer(cid):
        w = writers.get(cid)
        if w is None:
            w = open(os.path.join(a.outdir, f"tls_part{cid:03d}.pcap"), "wb")
            w.write(gh)
            writers[cid] = w
        return w

    for ts_s, ts_us, pkt, orig in records:
        h = rec_hdr.pack(ts_s, ts_us, len(pkt), orig)
        total += 1
        if total % 2_000_000 == 0:
            print(f"  {total:,} packets read, {n_tls:,} TLS connections, "
                  f"{time.time() - t0:.0f}s", flush=True)

        off = _l3_offset(linktype, pkt)
        if off is None or len(pkt) < off + 20:
            continue
        ihl = (pkt[off] & 0x0F) * 4
        if pkt[off + 9] != 6:                       # TCP only
            continue
        frag = struct.unpack_from("!H", pkt, off + 6)[0]
        if frag & 0x1FFF:                           # non-first IP fragment
            continue
        tcp = off + ihl
        if len(pkt) < tcp + 20:
            continue
        ipv4_tcp += 1
        src, dst = pkt[off + 12:off + 16], pkt[off + 16:off + 20]
        sport, dport = struct.unpack_from("!HH", pkt, tcp)
        flags = pkt[tcp + 13]
        doff = (pkt[tcp + 12] >> 4) * 4
        tot_len = struct.unpack_from("!H", pkt, off + 2)[0]
        payload_len = tot_len - ihl - doff
        a_ep, b_ep = (src, sport), (dst, dport)
        key = (a_ep, b_ep) if a_ep < b_ep else (b_ep, a_ep)
        d = (src, sport)

        st = conns.get(key)
        if flags & 0x02 and not flags & 0x10:       # bare SYN: new connection
            if st is not None and st[0] == 1:
                pass                                # port reuse: keep first one
            else:
                conns[key] = None
            continue
        if payload_len <= 0:
            continue
        p0 = tcp + doff
        if st is None:
            if key not in conns:
                # connection started before the capture: no SYN seen.
                # Still eligible if its first payload is a ClientHello record.
                pass
            if len(pkt) > p0 + 5 and pkt[p0] == 0x16 and pkt[p0 + 1] == 3 \
                    and pkt[p0 + 5] == 0x01:        # handshake record, ClientHello
                st = [1, n_tls // a.chunk, {}]
                n_tls += 1
            else:
                st = [0, None, None]
            conns[key] = st
        if st[0] != 1:
            continue
        kept = st[2].get(d, 0)
        if kept >= a.keep:
            continue
        st[2][d] = kept + 1
        writer(st[1]).write(h + pkt)
        kept_pkts += 1

    for w in writers.values():
        w.close()
    summary = {
        "input": os.path.basename(a.pcap),
        "input_bytes": os.path.getsize(a.pcap),
        "input_format": "pcapng" if first == b"\x0a\x0d\x0d\x0a" else "pcap",
        "linktype": linktype,
        "packets_read": total,
        "ipv4_tcp_packets": ipv4_tcp,
        "tcp_connections_with_payload": sum(1 for v in conns.values() if v),
        "tls_connections_kept": n_tls,
        "packets_kept": kept_pkts,
        "keep_per_direction": a.keep,
        "output_files": sorted(os.path.basename(w.name) for w in writers.values()),
        "seconds": round(time.time() - t0, 1),
    }
    json.dump(summary, open(os.path.join(a.outdir, "prefilter_summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
