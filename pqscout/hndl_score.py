"""Harvest-Now-Decrypt-Later exposure scoring.

Transparent, documented rubric -- every score can be explained and audited.
Score = quantum_vulnerability x data_longevity x observability, 0-100.
"""
from .tls_constants import PQ_SAFE_GROUPS

# 1. How breakable is the key exchange by a future quantum computer?
KEX_VULNERABILITY = {
    "RSA":   1.00,   # Shor breaks outright; no forward secrecy either
    "DHE":   0.95,
    "ECDHE": 0.90,   # Shor breaks, but forward secrecy limits blast radius
    None:    0.70,   # unknown -> assume vulnerable, flag for review
}

# 2. How long must traffic on this port stay confidential? (data shelf-life)
PORT_LONGEVITY = {
    443: 0.60, 8443: 0.60,          # general web
    993: 0.90, 995: 0.90, 465: 0.90, 587: 0.90,   # mail: long-lived, sensitive
    636: 0.95,                       # LDAPS: credentials/directory
    5432: 0.85, 3306: 0.85, 1433: 0.85,           # databases
    22: 0.80,                        # SSH: admin sessions, keys
}
DEFAULT_LONGEVITY = 0.65

BANDS = [(70, "CRITICAL"), (50, "HIGH"), (30, "MEDIUM"), (0, "LOW")]   # plus REVIEW for incomplete captures


def score_observation(obs, longevity=None, observability=1.0):
    """Return (score 0-100, band, human-readable rationale)."""
    group = obs.named_group

    if group and group in PQ_SAFE_GROUPS:
        return 0.0, "LOW", (
            f"Key exchange uses {group}, a post-quantum/hybrid group. "
            "Not exposed to harvest-now-decrypt-later.")

    vuln = KEX_VULNERABILITY.get(obs.key_exchange, 0.70)
    incomplete = getattr(obs, "incomplete", False) and not obs.selected_cipher
    longev = longevity if longevity is not None else PORT_LONGEVITY.get(
        obs.dport, DEFAULT_LONGEVITY)
    score = round(vuln * longev * observability * 100, 1)

    band = next(b for threshold, b in BANDS if score >= threshold)
    if incomplete:
        # A TCP gap stopped reassembly before the negotiated suite was seen.
        # Keep the cautious "assume vulnerable" score so the asset is not
        # dropped from the inventory, but label it REVIEW rather than giving
        # it a risk band it has not earned.
        band = "REVIEW"

    kex = obs.key_exchange or "unknown"
    parts = []
    if incomplete:
        parts.append("capture incomplete (TCP sequence gap): negotiated cryptography "
                     "not observed, re-capture to assess")
    parts.append(f"{kex} key exchange is quantum-vulnerable (factor {vuln:.2f})")
    if group:
        parts.append(f"negotiated group {group} is classical")
    parts.append(f"port {obs.dport} data-longevity factor {longev:.2f}")
    if obs.key_exchange == "RSA":
        parts.append("no forward secrecy: past sessions decryptable from the private key")
    return score, band, "; ".join(parts)
