# Baseline comparison: PQ-Scout vs Nmap ssl-enum-ciphers

## Why this comparison, and why it isn't apples-to-apples

Nmap's `ssl-enum-ciphers` script is the closest widely-used equivalent to
part of what PQ-Scout does, so it's the natural baseline — but the two
tools are not solving the same problem, and the comparison is more useful
for being honest about that than for producing one combined score.

Nmap enumerates: it opens one TLS connection per cipher suite it tests
against the target, to build a complete picture of everything the server
is willing to negotiate. That is thorough, but active — every one of
those connections is visible to the server (and to anything watching the
network for repeated, rapid handshakes from one source).

PQ-Scout observes: it never connects to anything. It reports only what a
single real client session happened to negotiate, passively, from
traffic it was already in a position to see. That is a strict subset of
what Nmap finds, by design — being passive means only ever seeing what
actually happened, not everything that could.

## Method

Three openssl test servers were started with a protocol-version policy
only (e.g. "TLS 1.2 only"), leaving many ciphers available — a realistic
admin setting, not a pinned single suite. Nmap was run against each to
enumerate its full supported set. Separately, one real client connection
was made to an identically-configured server instance, requesting one
specific cipher, and sniffed. The question: is PQ-Scout's one passive
observation a genuine member of the set Nmap independently confirmed the
server supports?

## Result

| Case | PQ-Scout observed | In Nmap's confirmed set? | Nmap's set size |
|---|---|---|---|
| TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384 | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | **Yes** | 20 |
| TLS 1.2, AES128-SHA | `TLS_RSA_WITH_AES_128_CBC_SHA` | **Yes** | 20 |
| TLS 1.3, X25519 | `TLS_AES_256_GCM_SHA384` | **Yes** | 3 |

3/3. PQ-Scout's passive, zero-connection read agrees with Nmap's active,
many-connection enumeration in every case tested.

## A naming inconsistency worth recording

The first run of this comparison showed the TLS 1.3 case as a
*mismatch* — not because either tool was wrong, but because Nmap's
`ssl-enum-ciphers` script names TLS 1.3 cipher suites
`TLS_AKE_WITH_AES_256_GCM_SHA384`, while PQ-Scout (and the IANA TLS
Cipher Suite Registry / RFC 8446 itself) use `TLS_AES_256_GCM_SHA384`.
Confirmed by running Nmap directly against a TLS-1.3-only server and
reading its raw output, rather than assumed. The comparison script
normalises Nmap's TLS 1.3 naming before comparing. This is a small
detail, but it is exactly the kind of thing that produces a false
"disagreement" between two correct tools if it isn't checked by hand —
worth a sentence in the methodology section.

## What this comparison is and isn't evidence of

It is evidence that PQ-Scout's handshake parsing produces results an
independent, widely-trusted tool corroborates — a real (if small-scale)
cross-validation, not just internal self-consistency.

It is not evidence that PQ-Scout can replace Nmap for the enumeration
task, and it was never meant to: PQ-Scout cannot tell you everything a
server supports, only what was actually used. That difference is the
tradeoff the whole thesis is about — passive/agentless costs coverage
and buys silence. Nmap's 20-vs-1 and 3-vs-1 set sizes above are a direct,
honest illustration of the size of that tradeoff.
