"""Check PQ-Scout's codepoint tables against the IANA TLS registries.

A parser can be perfectly consistent with itself and still be wrong if its
lookup tables are wrong -- the constructed-ground-truth batch would never
notice, because it only exercised the groups OpenSSL 3.0 could negotiate.
This test compares the post-quantum entries against values copied from the
IANA "TLS Supported Groups" registry (tls-parameters-8.csv, retrieved
14 Oct 2026), and, if network access is available, against the live CSV.

Run:  python tests/test_registry_conformance.py
"""
import csv, io, os, sys, urllib.request
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pqscout.tls_constants import NAMED_GROUPS, PQ_SAFE_GROUPS

# Snapshot of the IANA registry entries that matter for HNDL scoring.
IANA_SNAPSHOT = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519",
    512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024",
    4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
    25497: "X25519Kyber768Draft00", 25498: "SecP256r1Kyber768Draft00",
}
LIVE_URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv"


def live_registry():
    try:
        raw = urllib.request.urlopen(LIVE_URL, timeout=15).read().decode()
    except Exception as e:
        print(f"  (live IANA check skipped: {type(e).__name__})")
        return None
    out = {}
    for row in csv.reader(io.StringIO(raw)):
        if row and row[0].isdigit():
            out[int(row[0])] = row[1].replace(" (OBSOLETE)", "").strip()
    return out


def check(reference, label):
    failures = 0
    for code, name in reference.items():
        if code not in IANA_SNAPSHOT:
            continue
        got = NAMED_GROUPS.get(code)
        status = "OK  " if got == name else "FAIL"
        failures += got != name
        print(f"  {status} 0x{code:04x} IANA={name:<26} pqscout={got}")
    # every PQ-safe label must map back to a real codepoint
    known = set(NAMED_GROUPS.values())
    for g in PQ_SAFE_GROUPS:
        if g not in known:
            print(f"  FAIL PQ_SAFE_GROUPS entry {g!r} has no codepoint")
            failures += 1
    print(f"  {label}: {'PASS' if not failures else f'{failures} FAILURE(S)'}\n")
    return failures


if __name__ == "__main__":
    print("Against stored IANA snapshot:")
    f = check(IANA_SNAPSHOT, "snapshot")
    live = live_registry()
    if live:
        print("Against live IANA registry:")
        f += check(live, "live")
    sys.exit(1 if f else 0)
