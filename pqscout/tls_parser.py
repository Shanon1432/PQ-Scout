"""Passive TLS handshake parser.

Reads TLS records from TCP payloads and extracts the cryptographic
parameters that were negotiated. Never inspects application data --
only the handshake, which is sent in the clear before encryption starts.
"""
import struct
from dataclasses import dataclass, field
from typing import Optional, List
from .tls_constants import (
    TLS_VERSIONS, CIPHER_SUITES, NAMED_GROUPS,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE,
)


@dataclass
class HandshakeObservation:
    """What we learned about one TLS handshake."""
    src: str = ""
    dst: str = ""
    dport: int = 0
    sport: int = 0                          # client port (used to match
                                             # connections in cross-checks)
    legacy_version: Optional[str] = None
    negotiated_version: Optional[str] = None
    offered_ciphers: List[str] = field(default_factory=list)
    selected_cipher: Optional[str] = None
    key_exchange: Optional[str] = None      # e.g. ECDHE / RSA
    named_group: Optional[str] = None       # e.g. x25519 / X25519MLKEM768
    offered_groups: List[str] = field(default_factory=list)
    signature_alg: Optional[str] = None     # e.g. RSA / ECDSA
    server_name: Optional[str] = None
    hello_retry: bool = False               # True if the server sent a TLS 1.3
                                             # HelloRetryRequest before agreeing
    incomplete: bool = False                # True if a TCP sequence gap
                                             # was detected during reassembly
                                             # (see pcap_reader._streams)

    def asset_id(self) -> str:
        return f"{self.dst}:{self.dport}"


def _u16(b, i):  return struct.unpack_from("!H", b, i)[0]
def _u24(b, i):  return struct.unpack_from("!I", b"\x00" + b[i:i+3], 0)[0]


def iter_handshake_messages(payload: bytes):
    """Yield (msg_type, body) for each handshake message in a TCP payload."""
    i = 0
    n = len(payload)
    while i + 5 <= n:
        ctype = payload[i]
        if ctype not in (20, 21, 22, 23) or payload[i + 1] != 3:
            break                           # not a TLS record at all -> stop
        rec_len = _u16(payload, i + 3)
        rec = payload[i + 5 : i + 5 + rec_len]
        i += 5 + rec_len
        if ctype != 22:
            # ChangeCipherSpec (20), Alert (21) or encrypted data (23):
            # skip over it rather than stopping. The original version
            # stopped here, so after a TLS 1.3 HelloRetryRequest (which is
            # followed by a compatibility ChangeCipherSpec) it never saw the
            # second ClientHello or the real ServerHello. Found by the
            # post-quantum experiment's P-256 case (tests/pq_hybrid_experiment.py).
            continue
        j = 0
        while j + 4 <= len(rec):
            msg_type = rec[j]
            msg_len = _u24(rec, j + 1)
            body = rec[j + 4 : j + 4 + msg_len]
            if len(body) < msg_len:         # truncated / spans records
                break
            yield msg_type, body
            j += 4 + msg_len


def _parse_extensions(ext_blob: bytes, obs: HandshakeObservation, is_server: bool):
    i = 0
    while i + 4 <= len(ext_blob):
        etype = _u16(ext_blob, i)
        elen = _u16(ext_blob, i + 2)
        data = ext_blob[i + 4 : i + 4 + elen]
        i += 4 + elen

        if etype == EXT_SUPPORTED_GROUPS and not is_server:
            if len(data) >= 2:
                ln = _u16(data, 0)
                for k in range(2, 2 + ln, 2):
                    g = _u16(data, k)
                    obs.offered_groups.append(NAMED_GROUPS.get(g, f"0x{g:04x}"))

        elif etype == EXT_SUPPORTED_VERSIONS:
            if is_server and len(data) >= 2:
                obs.negotiated_version = TLS_VERSIONS.get(_u16(data, 0))
            elif len(data) >= 1:
                ln = data[0]
                vers = [_u16(data, k) for k in range(1, 1 + ln, 2)]
                best = max((v for v in vers if v in TLS_VERSIONS), default=None)
                if best:
                    obs.negotiated_version = obs.negotiated_version or None

        elif etype == EXT_KEY_SHARE:
            # ServerHello key_share = the group actually used
            if is_server and len(data) >= 2:
                g = _u16(data, 0)
                obs.named_group = NAMED_GROUPS.get(g, f"0x{g:04x}")

        elif etype == 0 and not is_server:   # SNI
            if len(data) >= 5:
                nlen = _u16(data, 3)
                obs.server_name = data[5 : 5 + nlen].decode("utf-8", "replace")
    return obs


def parse_client_hello(body: bytes, obs: HandshakeObservation):
    obs.legacy_version = TLS_VERSIONS.get(_u16(body, 0))
    i = 2 + 32                                  # version + random
    sid_len = body[i]; i += 1 + sid_len
    cs_len = _u16(body, i); i += 2
    for k in range(i, i + cs_len, 2):
        cid = _u16(body, k)
        entry = CIPHER_SUITES.get(cid)
        obs.offered_ciphers.append(entry[0] if entry else f"0x{cid:04x}")
    i += cs_len
    comp_len = body[i]; i += 1 + comp_len
    if i + 2 <= len(body):
        ext_len = _u16(body, i)
        _parse_extensions(body[i + 2 : i + 2 + ext_len], obs, is_server=False)
    return obs


def parse_server_hello(body: bytes, obs: HandshakeObservation):
    obs.legacy_version = obs.legacy_version or TLS_VERSIONS.get(_u16(body, 0))
    i = 2 + 32
    sid_len = body[i]; i += 1 + sid_len
    cid = _u16(body, i); i += 2
    entry = CIPHER_SUITES.get(cid)
    if entry:
        obs.selected_cipher = entry[0]
        obs.key_exchange = entry[1]
        obs.signature_alg = entry[2]
    else:
        obs.selected_cipher = f"0x{cid:04x}"
    i += 1                                      # compression
    server_version = TLS_VERSIONS.get(_u16(body, 0))
    obs.negotiated_version = None               # set by supported_versions, if sent
    if i + 2 <= len(body):
        ext_len = _u16(body, i)
        _parse_extensions(body[i + 2 : i + 2 + ext_len], obs, is_server=True)
    if obs.negotiated_version is None:
        # No supported_versions extension, so this is TLS 1.2 or earlier and
        # the ServerHello's own version field IS the negotiated version.
        # The original code fell back to the ClientHello's version instead,
        # which is only what the client offered. Testing on CIC-IDS2017
        # (tests/cicids_experiment.py) found 222 connections where a server
        # chose TLS 1.0 or 1.1 but PQ-Scout reported TLS 1.2, and 8,320
        # where a later TCP gap left the version blank although the
        # ServerHello itself had been read in full.
        obs.negotiated_version = server_version
    # TLS 1.3 has no kex in the cipher suite -- it's the key_share group
    if obs.negotiated_version == "TLS 1.3" and obs.named_group:
        obs.key_exchange = obs.key_exchange or "ECDHE"
    return obs
