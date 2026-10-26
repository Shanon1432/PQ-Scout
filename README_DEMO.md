# PQ-Scout — Demo Runbook

## What this is
A passive cryptographic discovery tool. It reads TLS handshakes from packet
captures, produces a CycloneDX CBOM inventory, and scores each asset for
"harvest-now, decrypt-later" quantum risk.

---

## 1. One-time setup (do this BEFORE any demo)

```
python --version          # need Python 3.8+
pip install scapy
```

Then from the project folder:
```
python pqscout_run.py data/multiflow.pcap
```
If you see a ranked table of 8 assets, you are ready.

> **Windows note:** analysing saved .pcap files works fine on Windows.
> *Capturing* new traffic (tests/batch_experiment.py) needs Linux or WSL,
> because it sniffs the loopback interface. Do not attempt live capture
> on Windows in a meeting — demo the analysis instead.

---

## 2. The three-command demo

### Command 1 — run the tool on a real capture
```
python pqscout_run.py data/multiflow.pcap
```
**Say:** "This is one packet capture containing eight TLS connections
interleaved together. The tool separates the flows, identifies the
cryptography in each, and ranks them by quantum risk. Static RSA scores
highest because it has no forward secrecy."

### Command 2 — show the standards-compliant output
```
python pqscout_run.py data/multiflow.pcap -o results/demo_cbom.json
```
Then open `results/demo_cbom.json`.
**Say:** "That's a CycloneDX 1.6 Cryptographic Bill of Materials — the
industry standard format, so the output is interoperable rather than
proprietary."

### Command 3 — reproduce the whole evaluation
```
python tests/evaluate.py
```
**Say:** "This re-runs the full evaluation against all 41 test cases.
Ground truth is constructed: I configured each server with a known cipher
suite, so the correct answer is known before the tool runs. It compares
the tool's output against those configurations and computes the metrics."

---

## 3. "How did you produce one result?" — the walkthrough

Explain the chain for a single case, e.g. `tls12_aes128_sha`:

1. **Configure** — the harness starts an OpenSSL server forced to
   `AES128-SHA`. *That configuration is the ground truth.*
2. **Capture** — traffic is sniffed to `data/batch/tls12_aes128_sha.pcap`.
3. **Label** — the intended answer is written to
   `data/batch/ground_truth.json`.
4. **Analyse** — the parser reassembles the TCP stream and reads the
   ServerHello, which names the selected cipher suite.
5. **Compare** — `tests/evaluate.py` checks the parsed value against the
   labelled value. Match = correct.

Show it live:
```
python pqscout_run.py data/batch/tls12_aes128_sha.pcap
```
Then show the matching entry in `data/batch/ground_truth.json`.

---

## 4. Files worth opening if asked
| File | What it shows |
|---|---|
| `pqscout/tls_parser.py` | The handshake parser — the core technical work |
| `pqscout/hndl_score.py` | The risk rubric, with weightings documented |
| `pqscout/pcap_reader.py` | Reassembly + the sequence-gap hardening fix (see stress findings below) |
| `tests/batch_experiment.py` | How the 41 test cases are generated |
| `tests/evaluate.py` | How precision/recall are computed |
| `tests/stress_experiment.py` | Adversarial testing: fragmentation, loss, reorder, duplication, mid-session capture |
| `tests/nmap_baseline.py` | Cross-validation against Nmap `ssl-enum-ciphers` |
| `data/batch/ground_truth.json` | The labelled test matrix |
| `results/metrics.json` | The 41-case evaluation numbers |
| `results/stress_findings.md` | The packet-loss bug found and fixed by adversarial testing |
| `results/nmap_baseline_findings.md` | The Nmap cross-validation write-up |
| `results/cicids2017_feasibility.md` | Early feasibility note on CIC-IDS2017 (superseded: Experiment 7 later ran one public day, see `results/cicids2017_findings.md`) |

### Phase 2 — adversarial / degraded-condition testing
```
python tests/stress_experiment.py
```
**Say:** "The 41-case evaluation used clean, single-handshake captures.
This phase deliberately damages traffic — fragmentation, packet loss,
reordering, duplication, a sniffer starting mid-session — the way a real
network actually behaves. It found a real bug: a single lost packet
landing on the cipher-suite bytes made the tool report a confident but
*wrong* answer instead of failing safe. I fixed the reassembly logic to
stop at sequence gaps instead of bridging them, re-ran the test, and the
dangerous failure mode is gone — it now reports 'incomplete' instead of
guessing. Before/after and the fix itself are documented in
`results/stress_findings.md`."

### Phase 3 — Nmap baseline
```
python tests/nmap_baseline.py
```
**Say:** "Nmap's ssl-enum-ciphers actively probes a server with one
connection per cipher it tests, to enumerate everything the server
supports. PQ-Scout makes zero connections and only reports what one real
session actually used. I checked that PQ-Scout's passive read agrees
with what Nmap independently confirms — it did, 3 for 3 — which is a
cross-validation against an established tool, not just internal
self-consistency. The size difference between the two (e.g. Nmap found
20 ciphers, PQ-Scout reported the 1 that was actually used) is itself the
honest illustration of the passive/active tradeoff this thesis is about."

## 5. Repository history
```
git log --oneline
```
Shows development progression — required as evidence under the assignment brief.
