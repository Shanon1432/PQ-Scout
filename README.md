# PQ-Scout v0.5

**Passive network-based cryptographic discovery and harvest-now, decrypt-later (HNDL) risk prioritisation for post-quantum migration.**

PQ-Scout reads TLS handshakes from saved packet captures (`.pcap`/`.pcapng`). It does not send any packets and does not decrypt any content. For each server it reports the TLS version, cipher suite, key exchange and named group it observed. It scores each server for HNDL exposure and writes a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM).

| | |
|> **Public repository note.** This public copy is shared for assessment and review of the MSc project *PQ-Scout* (Coventry University, 7005SCN). Under the CW2 declaration, copyright belongs to Coventry University. To avoid re-publishing third-party server addresses from the CIC-IDS2017 dataset, this copy leaves out the Wireshark export (`data/cicids2017/tshark_friday.tsv`) and the Experiment 7 CBOM (`results/cicids2017_cbom.json`), and removes server addresses from the Experiment 7 result files. Everything else, including all lab captures, is included: `tests/verify_all.py` (6/6) and `tests/check_report_numbers.py` (20/20) run as described below. `tests/check_cicids_numbers.py` and the Experiment 7 comparison need the full artefact (`PQScout_v0.5.zip`, submitted with the report) or the files regenerated from the public capture (Section 5).

---|---|
| Author | Asitha Shanon Perera (SID 16298048) |
| Module | 7005SCN Individual Research Project, MSc Cyber Security, Coventry University |
| Supervisor | Dr Yuhang Xu |
| Ethics approval | P195945 (Low Risk, approved 5 August 2026) |
| Version | v0.5 (October 2026) |
| Report | *PQ-Scout: Passive Network-Based Cryptographic Discovery and Harvest-Now-Decrypt-Later Risk Prioritisation for Post-Quantum Migration* |

---

## 1. What is in this folder

```
pqscout/
├── README.md                 this file
├── README_DEMO.md            short runbook for a live demonstration
├── pqscout_run.py            command-line entry point
├── pqscout/                  the tool
│   ├── pcap_reader.py        reads captures, reassembles TCP streams (gap and overlap handling)
│   ├── tls_parser.py         parses ClientHello / ServerHello / HelloRetryRequest
│   ├── tls_constants.py      cipher-suite and named-group tables (IANA codepoints)
│   ├── hndl_score.py         the HNDL scoring rubric
│   ├── cbom.py               builds the CycloneDX 1.6 CBOM
│   └── cli.py                ranked table output
├── tests/                    experiment harnesses and checks (Section 4)
├── data/                     saved captures with their ground truth
│   ├── batch/                41-case test matrix (Experiment 1)
│   ├── multiflow.pcap        8 interleaved connections (Experiment 2)
│   ├── stress/               damaged captures (Experiment 3)
│   ├── nmap_baseline/        Nmap comparison captures (Experiment 4)
│   ├── pq_hybrid/            Go ML-KEM hybrid captures (Experiment 5)
│   └── cicids2017/           Wireshark export for Experiment 7 (tshark_friday.tsv)
├── results/                  results JSON, findings write-ups, CBOMs and figures
└── .git/                     full development history (see Section 9)
```

---

## 2. Requirements

**To run the tool and reproduce every reported result (any OS):**

- Python 3.11 or later. It was tested with Python 3.11 and Python 3.14.4.
- Scapy. It was tested with 2.7.0 and 2.8.0. Install it with:
  ```
  python -m pip install scapy
  ```

**Optional:**

| Needed for | Install |
|---|---|
| CBOM schema validation (`tests/validate_cbom.py`) | `python -m pip install "cyclonedx-python-lib[json-validation]"` |
| Rebuilding the report figures (`tests/make_figures.py`) | `python -m pip install matplotlib` |
| Repeating Experiment 7 from the raw capture | The CIC-IDS2017 `Friday-WorkingHours.pcap` (8.2 GB). It is not included (Section 5). |
| Regenerating the Wireshark export | Wireshark 4.x (`tshark`). It was tested with 4.6.9. |
| Capturing **new** lab traffic (Section 6) | Linux or WSL with OpenSSL 3, Go 1.24 and Nmap. You do not need these to reproduce any reported result. |

On Windows, Scapy prints `WARNING: No libpcap provider available`. You can ignore it, because PQ-Scout only reads saved files.

---

## 3. Quick start

Run all commands from the `pqscout` folder (the one that contains `pqscout_run.py`).

```
python pqscout_run.py data/multiflow.pcap
```

This prints a table of the 8 server assets in the capture, ranked by HNDL score, with the reason for each of the top scores.

To also write a CBOM:

```
python pqscout_run.py data/multiflow.pcap -o results/my_cbom.json
```

To analyse your own capture, give its path instead. Wildcards and several files are accepted:

```
python pqscout_run.py path/to/capture.pcap
python pqscout_run.py "captures/*.pcap" -o results/cbom.json
```

### Reading the output

| Column | Meaning |
|---|---|
| SCORE | HNDL score, 0–100 |
| BAND | CRITICAL (≥70), HIGH (≥50), MEDIUM (≥30), LOW (<30), or **REVIEW** when a TCP gap stopped the handshake from being read (re-capture before deciding) |
| ASSET | server IP:port |
| TLS / KEX / GROUP / CIPHER | negotiated version, key-exchange type, named group and cipher suite |

**Score = key-exchange vulnerability × data longevity × observability × 100**

| Factor | Values |
|---|---|
| Key exchange | RSA 1.00, DHE 0.95, ECDHE 0.90, unknown 0.70 |
| Data longevity by port | web 443/8443 0.60; mail 465/587/993/995 0.90; LDAPS 636 0.95; databases 0.85; SSH 22 0.80; other 0.65 |
| Observability | 1.0 for passively observed traffic |

A post-quantum or hybrid group, such as X25519MLKEM768, scores 0 (LOW). These weights were set by judgement and have not been calibrated (see Section 8).

---

## 4. Reproducing the reported results

Each check below runs from the saved files in the artefact. None of them needs network access or new captures.

| Command | What it checks | Expected |
|---|---|---|
| `python tests/verify_all.py` | Re-runs Experiments 1–6 from the saved captures against their ground truth (about 10 s) | `6/6 experiments reproduce from saved captures` |
| `python tests/check_report_numbers.py` | The 20 figures quoted in report Sections 3–6 | `20/20` |
| `python tests/check_cicids_numbers.py` | The 18 Experiment 7 (CIC-IDS2017) figures | `18/18` |
| `python tests/validate_cbom.py` | Builds a fresh CBOM and validates it against CycloneDX 1.6 (needs the optional library) | `VALID` in normal and strict modes |
| `python tests/evaluate.py` | Recomputes precision / recall / F1 for the 41-case matrix | TLS detection P = R = F1 = 1.000 (39 evaluated cases) |
| `python tests/make_figures.py` | Rebuilds the report figures from `results/*.json` | PNGs in `results/figures/` |

If a check prints `FAIL`, compare the value with Appendices D and G of the report. Timings vary between computers, but the counts and agreement figures should not.

### The seven experiments

| # | Experiment | Data | Script | Result file |
|---|---|---|---|---|
| 1 | Ground-truth accuracy (41 cases, 5 negative controls) | `data/batch/` | `tests/batch_experiment.py`, `tests/evaluate.py` | `results/metrics.json` |
| 2 | Eight interleaved connections | `data/multiflow.pcap` | `tests/robustness_multiflow.py` | `results/multiflow.json` |
| 3 | Damaged traffic (fragmentation, reordering, duplication, targeted loss, late start) | `data/stress/` | `tests/stress_experiment.py` | `results/stress_metrics.json`, `results/stress_findings.md` |
| 4 | Nmap `ssl-enum-ciphers` comparison | `data/nmap_baseline/` | `tests/nmap_baseline.py` | `results/nmap_baseline.json` |
| 5 | Real ML-KEM hybrid handshakes (Go 1.24) | `data/pq_hybrid/` | `tests/pq_hybrid_experiment.py` | `results/pq_hybrid.json` |
| 6 | Group codepoints against the IANA registry | built in | `tests/test_registry_conformance.py` | `results/registry_conformance.txt` |
| 7 | Public CIC-IDS2017 capture compared with Wireshark | `data/cicids2017/tshark_friday.tsv` | `tests/cicids_prefilter.py`, `tests/cicids_experiment.py` | `results/cicids2017.json`, `results/cicids2017_findings.md` |

---

## 5. Experiment 7 from the raw capture (optional)

The 8.2 GB capture is not included in the artefact because of its size. It is available from its publisher.

1. Register on the Canadian Institute for Cybersecurity dataset portal, <https://www.unb.ca/cic/datasets/ids-2017.html>. Download `Friday-WorkingHours.pcap` and its `.md5` file.
2. Check the MD5. It should be `7366c552425956e610bd69f57feb7e7a`.
   ```
   certutil -hashfile Friday-WorkingHours.pcap MD5        (Windows)
   md5sum Friday-WorkingHours.pcap                          (Linux)
   ```
3. Keep only the opening packets of each TLS connection (about 1 minute). Expect 52,544 TLS connections and 581,728 packets.
   ```
   python tests/cicids_prefilter.py <path>/Friday-WorkingHours.pcap data/cicids2017/prefilter
   ```
4. Run PQ-Scout and compare it with Wireshark (about 2–3 minutes). Version and cipher-suite agreement should both be 52,162 of 52,164.
   ```
   python tests/cicids_experiment.py data/cicids2017/prefilter --tshark data/cicids2017/tshark_friday.tsv
   ```
5. (Optional) Regenerate the Wireshark export yourself:
   ```
   tshark -r Friday-WorkingHours.pcap -n -Y "tls.handshake.type==1 || tls.handshake.type==2" -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=; -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extensions.supported_version -e tls.handshake.extensions_key_share_group -e tls.handshake.extensions_server_name > data/cicids2017/tshark_friday.tsv
   ```

The comparison measures **agreement with Wireshark, not accuracy**, because the dataset has no labels for TLS fields.

**Please cite the dataset whenever you use it:** Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP)*, 108–116. https://doi.org/10.5220/0006639801080116

---

## 6. Capturing new lab traffic (Linux or WSL only)

The harnesses start local OpenSSL or Go servers and record the handshakes on the loopback interface (`lo`). The expected answer is fixed before each capture. Packet capture usually needs root (`sudo`).

```
openssl req -x509 -newkey rsa:2048 -keyout data/key.pem -out data/cert.pem -days 365 -nodes -subj "/CN=pqscout-lab.local"
sudo python3 tests/batch_experiment.py        # Experiment 1, then: python3 tests/evaluate.py
sudo python3 tests/robustness_multiflow.py    # Experiment 2
sudo python3 tests/stress_experiment.py       # Experiment 3
sudo python3 tests/nmap_baseline.py           # Experiment 4 (needs nmap)
sudo python3 tests/pq_hybrid_experiment.py    # Experiment 5 (builds tests/pqtls/pqtls.go with Go 1.24)
```

The key and certificate are test-only files and are not included in the artefact (see `.gitignore`).

---

## 7. Ethics, law and responsible use

- **Approval.** This project ran under Coventry University ethics approval **P195945** (Low Risk). It analysed only:
  - traffic generated by the author in an isolated test environment;
  - the public CIC-IDS2017 dataset.

  No traffic was captured from University, third-party, public or live networks.
- **Data in this artefact.** The lab captures contain only local test traffic. The Experiment 7 files are derived from the public CIC-IDS2017 testbed capture: `data/cicids2017/tshark_friday.tsv`, `results/cicids2017_cbom.json` and `results/cicids2017.json`. They therefore contain third-party server IP addresses and server names (SNI) as they appeared in that 2017 dataset. No application data was decrypted or analysed.
- **Use only on traffic you are authorised to monitor.** Capturing or examining other people's network traffic without authority can break the law. In the UK this includes the Computer Misuse Act 1990 and the Investigatory Powers Act 2016 and its regulations, and data-protection law also applies. Use an approved monitoring point or existing capture files, keep only the metadata you need, and protect and delete the outputs according to a clear retention schedule.
- **Results support decisions; they are not a migration plan.** A passive inventory records only what was negotiated during the captured sessions.

---

## 8. Known limitations

- TLS over TCP only. QUIC, SSH and IPsec are not parsed, and STARTTLS (mail on 25/587) is not detected by the CIC-IDS2017 prefilter.
- The negotiated curve is not extracted for TLS 1.2 ECDHE.
- The cipher-suite table holds 27 suites. Five suites seen in CIC-IDS2017 were missing, so 154 connections were scored as "unknown" and under-scored.
- Connections with no ServerHello get the default "unknown" score (MEDIUM) rather than REVIEW.
- The HNDL weights were set by judgement and have not been calibrated. Port longevity has a large effect on the score.
- The Wireshark comparison measures agreement, not accuracy. CIC-IDS2017 is from 2017 and has no TLS 1.3 or post-quantum traffic.
- Most controlled cases came from one TLS implementation (OpenSSL 3.0.13). Go 1.24 was used for the post-quantum path.

---

## 9. Version history

The full history is in `.git` (`git log --oneline`). The main stages are:

| Date | Commit | Change |
|---|---|---|
| 8 Sep 2026 | `7a5b65d` | v0.1: TLS handshake parser, HNDL scorer, CycloneDX CBOM output |
| 8 Sep 2026 | `d5081fd` | 41-case ground-truth matrix and multi-flow test |
| 7 Oct 2026 | `0e5fc48` | Stress testing; reassembly fix (stop at TCP gaps) |
| 7 Oct 2026 | `4a2a972` | Nmap baseline comparison |
| 14 Oct 2026 | `4593742` | Real ML-KEM hybrid test; post-quantum codepoint and HelloRetryRequest fixes |
| 14 Oct 2026 | `6e2ad6b` | Incomplete captures labelled REVIEW |
| 14 Oct 2026 | `9cb8454`, `7d13177` | `verify_all.py`, `validate_cbom.py`, `check_report_numbers.py` |
| 15 Oct 2026 | `d0b41f8` | Experiment 7 (CIC-IDS2017 vs Wireshark); version source, CBOM validity at scale, and overlapping-retransmission fixes |
| 15 Oct 2026 | `c86e5e2` | Corrected description of the prefilter |

Commits `d5081fd` and `7a5b65d` are in the first repository (history from 8 September 2026). The second repository was created on 7 October 2026 from a backup copy (`849ab28`), so its history starts on that date. Appendix A of the report lists both.

To see a defect before it was fixed, check out an older commit into a separate folder. This leaves the submitted code unchanged:

```
git worktree add ../pqscout_before_reassembly_fix 849ab28
git worktree add ../pqscout_before_exp7_fixes 7d13177
```

Appendix H, Step 9 of the report shows what to run in these folders.

---

## 10. Use of AI

The author set the requirements, chose the tests, ran and reviewed the experiments, and is responsible for the results. The language, grammar and consistency was kept by the Claude (Anthropic). The report's AI Use Statement gives the details.

## 11. Copyright

Under the Coventry University CW2 declaration, the copyright of this project report and of any product developed as part of the project belongs to Coventry University (www.coventry.ac.uk/ipr). The CIC-IDS2017 dataset remains subject to its publisher's terms.
