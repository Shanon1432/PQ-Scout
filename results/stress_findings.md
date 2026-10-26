# Adversarial / degraded-condition stress testing

The first evaluation (41 cases, `results/metrics.json`) used clean,
single-handshake, loopback captures. Real passive monitoring is not that
tidy: packets fragment, arrive out of order, get duplicated by
retransmission, go missing, and a sniffer rarely starts listening at the
exact moment a connection begins. This test asks: does PQ-Scout stay
*correct*, or just stay *quiet*, when those things happen?

## Method

Three base cases (TLS 1.3/X25519, TLS 1.2/ECDHE-RSA, TLS 1.2/RSA) were
captured the same way as the main batch — server configuration fixed
first, so the correct answer is known before the capture happens — then
each base capture was deliberately damaged in five ways and re-analysed:

| Condition | What it simulates |
|---|---|
| fragmented | Every handshake segment re-split into 4–8 byte TCP pieces (low-MTU path) |
| reordered | Packets shuffled out of capture order (multi-path jitter) |
| duplicated | ~30% of segments duplicated (retransmission) |
| lossy | The exact TCP bytes carrying the negotiated cipher-suite ID deleted (genuine packet loss, targeted at the field being scored — not a random drop that might miss) |
| midsession | Every packet up to and including the full ServerHello removed (sniffer attaches late) |

Outcomes were classified against ground truth as **CORRECT**, **SAFE_MISS**
(tool reports nothing rather than guessing), **WRONG** (confident but
incorrect — the dangerous outcome), or **CRASH**.

## What was found, before any fix

| Condition | Correct | Safe miss | Wrong | Crash |
|---|---|---|---|---|
| fragmented / reordered / duplicated | 3/3 | 0 | 0 | 0 |
| **lossy** | 0/3 | 0 | **3/3** | 0 |
| midsession | 0/3 | 3/3 | 0 | 0 |

Fragmentation, reordering, and duplication were already handled correctly
— the reassembly step sorts by TCP sequence number and drops repeats, so
scrambled or doubled packets don't confuse it. Missing the whole
handshake (midsession) failed safely: no ServerHello, no claim made.

**Genuine packet loss did not fail safely.** Reassembly concatenated the
bytes on either side of the gap as if they were contiguous, and the
parser read the resulting (wrong) bytes as a real cipher-suite ID or
version number — in one case misreporting a TLS 1.3 connection as
TLS 1.2. A tool that silently reports the wrong cryptography is worse
than one that reports nothing, because nothing in the output signals
that anything went wrong.

## The fix

`pqscout/pcap_reader.py` now tracks the expected next sequence number
while reassembling each direction and stops at the first gap instead of
bridging it (`_reassemble`). The TLS-1.2 legacy-version fallback — used
for versions that don't carry an explicit negotiated-version extension —
no longer fires when reassembly was incomplete, since that fallback was
itself the source of the TLS-1.3-reported-as-TLS-1.2 error. Per-connection
parsing was also wrapped so a malformed stream can't take the rest of a
pcap down with it.

## After the fix

| Condition | Correct | Safe miss | Wrong | Crash |
|---|---|---|---|---|
| fragmented / reordered / duplicated | 3/3 | 0 | 0 | 0 |
| lossy | 0/3 | **3/3** | **0** | 0 |
| midsession | 0/3 | 3/3 | 0 | 0 |

Packet loss now degrades to "incomplete, no result" instead of a
confident wrong answer. Re-running the original 41-case batch and the
8-flow concurrency test after the fix reproduced identical results (39/39
and 8/8) — the change affects only damaged input, not the clean case.

## What this means for the thesis

This is the finding worth leading with in the critical-appraisal section:
the 100% scores on clean data say the parser logic is correct, not that
the tool is production-ready. The thing that actually needed hardening —
and the thing adversarial testing exists to find — was an *integrity*
gap, not an accuracy gap. It also gives the dissertation a legitimate
before/after engineering narrative: a concrete bug, found by a designed
test, fixed, and re-verified with no regression, which is a stronger
story for the Artefact and Problem Definition criteria than "it scored
100%" on its own.

## Honest limitations of this test

- Only one gap position per case was tested (targeted at the
  cipher-suite field specifically, since that's the field the risk score
  depends on). A gap elsewhere in the stream was not swept exhaustively.
- Loss was simulated by deleting bytes from a capture file, not produced
  by an actual lossy network path — real loss could also corrupt TCP
  checksums or trigger real retransmissions, which this harness does not
  model.
- Three base cases, not the full 41 — chosen to cover TLS 1.3, TLS 1.2
  ECDHE, and TLS 1.2 RSA (the three key-exchange families the HNDL score
  actually distinguishes between).
