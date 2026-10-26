# Experiment 7: PQ-Scout on independent public data (CIC-IDS2017)

Run 15 October 2026. Every number below is read from `results/cicids2017.json`,
`results/cicids2017_before_fix.json` or `results/cicids2017_cbom_validation_before_fix.txt`,
and is re-checked by `python tests/check_cicids_numbers.py`.

## Data

* **Dataset.** CIC-IDS2017 (Sharafaldin, Lashkari & Ghorbani, 2018), Canadian Institute for
  Cybersecurity, University of New Brunswick. This is the public dataset named in the ethics
  application (P195945). It was downloaded from the official portal after registration.
* **File.** `Friday-WorkingHours.pcap` (pcapng, 8,839,309,056 bytes, 9,997,874 packets). The MD5
  `7366c552425956e610bd69f57feb7e7a` matches the checksum published with the dataset. The
  labelled-flows archive `GeneratedLabelledFlows.zip` also matched its published MD5 but was not
  needed for this test.
* **Why Friday.** The Friday capture was the file downloaded. Any day of the dataset fits the
  approval, and the Friday file has normal user web and mail traffic alongside the botnet,
  port-scan and DDoS attack traffic.
* **Nature of the traffic.** The traffic is from a 2017 testbed. Simulated users on victim machines
  (192.168.10.0/24) browsed real internet services, so the TLS servers are real third-party
  servers as they were in July 2017. TLS 1.3 was not standardised until August 2018, so the
  capture has no TLS 1.3 traffic and no post-quantum key exchange. It tests the classical
  (TLS 1.0 to 1.2) path, not the post-quantum path.

## Method

1. `tests/cicids_prefilter.py` streamed the 8.2 GB file once in 63 s on the author's laptop. It kept
   only the first 8 data packets in each direction of TCP connections whose first payload is a TLS
   ClientHello: 52,544 connections and 581,728 packets. Everything after those opening packets is
   dropped. The opening packets can still include a few encrypted application-data records; these
   are never decrypted or analysed.
2. `tests/cicids_experiment.py` ran PQ-Scout on those files and built the CBOM.
3. **Independent reference.** Wireshark 4.6.9 (`tshark`) decoded the ClientHello and ServerHello of
   every connection in the **original full file**, independently of the prefilter and of
   PQ-Scout's parser. Wireshark is a widely used dissector, not ground truth, so the result is
   agreement, not accuracy.
4. PQ-Scout and Wireshark were matched per connection (client IP and port, server IP and port) and
   compared on the negotiated TLS version and the selected cipher suite. The TLS 1.3 group was not
   compared because the capture has no TLS 1.3.

## Results (after the fixes)

| Measure | Value |
|---|---|
| TLS handshakes PQ-Scout observed | 52,536 (52,223 with a ServerHello) |
| Connections where Wireshark decoded both hellos | 52,164 |
| ...of these, also reported by PQ-Scout | 52,164 (none missed) |
| Negotiated version agrees with Wireshark | 52,162 / 52,164 (99.996%) |
| Selected cipher suite agrees with Wireshark | 52,162 / 52,164 (99.996%) |
| CBOM (10,630 components) valid against CycloneDX 1.6 | normal and strict: VALID |
| PQ-Scout processing time (52,544 connections) | 161 s (cloud test environment); 207 s (laptop, before the fixes) |

**The 2 non-agreements.** On the full file Wireshark gave no value for these two connections.
The cause is likely reassembly in a long capture. When Wireshark was run on the trimmed copy of the
same connections, it decoded the ServerHello as `0xc030` (TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
TLS 1.2), which is PQ-Scout's answer. They are still counted as non-agreements.

**59 connections reported only by PQ-Scout.** Wireshark saw the ClientHello but could not reassemble
the ServerHello, because the capture recorded the server's segments out of order. In the example
inspected (a testbed client connecting to a public web server on port 443), the segment at sequence 2837 was captured
before sequences 1 and 1419, and Wireshark marked those two as retransmissions. PQ-Scout sorts by
sequence number. A manual decode of that ServerHello's bytes gave cipher `0xc02f`, which is
PQ-Scout's answer. These 59 are not counted as agreement.

## What the inventory shows

* **Key exchange, by connection (52,223 with a ServerHello).**
  * ECDHE: 44,017 (84.3%)
  * RSA: 6,378 (12.2%)
  * DHE: 1,674 (3.2%)
  * Suite not in PQ-Scout's table: 154 (0.3%)

  All of these are classical, so all are exposed to harvest-now-decrypt-later. RSA key transport
  also has no forward secrecy.
* **Version.**
  * TLS 1.2: 48,584 (93.0%)
  * TLS 1.0: 3,609 (6.9%)
  * TLS 1.1: 30 (0.1%)

  TLS 1.0 was negotiated with 934 server assets.
* **Assets.** There are 6,803 server assets (IP and port): 6,768 on port 443, 30 on port 465
  (SMTPS) and 5 on other ports. 1,028 assets used RSA key transport on at least one connection.
  548 assets used more than one key-exchange type, depending on what each client offered. A
  passive inventory therefore records what was actually negotiated, which can differ per client.
* **HNDL bands per asset (highest-scoring connection).**
  * CRITICAL: 30, all SMTPS on port 465 (mail longevity factor 0.90; ECDHE scores 81.0, RSA 90.0)
  * HIGH: 6,742
  * MEDIUM: 31 (suites missing from PQ-Scout's table, or no ServerHello captured)
  * LOW: 0
* **Post-quantum groups.** None were seen, as expected for 2017 traffic.

## Defects found by the independent data (fixed and re-tested)

| # | Defect | How it showed | Before → after |
|---|---|---|---|
| 5 | For TLS 1.0–1.2, the negotiated version was taken from the **ClientHello** (what the client offered) instead of the ServerHello (what the server chose). A later TCP gap also blanked the version even when the ServerHello had been read in full. | 222 connections reported TLS 1.2 where the server chose TLS 1.0/1.1 (confident errors). 8,320 had no version (safe misses). | Version agreement 43,616/52,158 (83.6%) → 52,162/52,164 (99.996%) |
| 6 | The CBOM was **invalid at scale**. It wrote `null` for unseen fields and one component per connection, so many connections to the same server gave duplicate components and bom-refs. Every lab capture had one connection per server, so lab validation never showed this. | CycloneDX validation failed (null `cipherSuites.name`, then `uniqueItems`). | INVALID → VALID (normal and strict); 52,536 components → 10,630 |
| 7 | **Overlapping TCP retransmissions** (bytes re-sent in differently sized segments) were treated as gaps. When only the ServerHello could be read, the connection was also recorded with a blank asset (`:0`). | 8,348 connections flagged incomplete. 6 connections that Wireshark decoded were missing. | Incomplete 8,348 → 186; missed 6 → 0 |

After all three fixes, all six earlier experiments still reproduce (`tests/verify_all.py` 6/6), and
the 20 report figures still match (`tests/check_report_numbers.py` 20/20).

## Limitations

* **No ground truth.** Agreement with Wireshark shows that two independent parsers read the same
  bytes the same way. It does not prove both are right. The 59 PQ-Scout-only connections show that
  the two tools handle reordering differently.
* **Coverage.** The capture is one day from one 2017 testbed, with roughly a dozen client machines
  and 2017-era browsers and servers. There is no TLS 1.3, no post-quantum traffic, no QUIC and no
  STARTTLS (mail on 587 or 25 that upgrades to TLS mid-session is not detected by the prefilter).
* **Prefilter.** The prefilter keeps only connections whose first payload in the capture is a
  ClientHello. Connections already open when the capture started are therefore skipped.
* **Cipher table.** PQ-Scout's cipher-suite table (27 suites) lacked 5 suites seen here: RC4 suites
  `0x0004`, `0x0005` and `0xc011`; `0x0016`; and `0xc009`. Together they cover 154 connections.
  These were scored as "unknown key exchange" (factor 0.70), although all five use a known
  classical key exchange (RSA, DHE or ECDHE, factors 0.90 to 1.00), so they were under-scored. Loading the full IANA
  cipher-suite registry would fix this.
* **Connections with no ServerHello.** The 313 such connections got the default "unknown" score
  (MEDIUM) rather than the REVIEW label used for incomplete captures. Treating "no ServerHello" as
  REVIEW would be more consistent.
* **Scoring.** The HNDL score depends heavily on the port. The 30 CRITICAL assets are all mail
  (port 465), which reflects the rubric's weights rather than a measured data lifetime. The weights
  remain uncalibrated.

## Reproduce

```text
# 1. Download Friday-WorkingHours.pcap from the CIC-IDS2017 portal; check MD5 7366c552425956e610bd69f57feb7e7a
python tests/cicids_prefilter.py <path>/Friday-WorkingHours.pcap data/cicids2017/prefilter
tshark -r <path>/Friday-WorkingHours.pcap -n -Y "tls.handshake.type==1 || tls.handshake.type==2" -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=; -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tls.handshake.type -e tls.handshake.version -e tls.handshake.ciphersuite -e tls.handshake.extensions.supported_version -e tls.handshake.extensions_key_share_group -e tls.handshake.extensions_server_name > data/cicids2017/tshark_friday.tsv
python tests/cicids_experiment.py data/cicids2017/prefilter --tshark data/cicids2017/tshark_friday.tsv
python tests/validate_cbom.py
python tests/check_cicids_numbers.py
```

The Wireshark export (`data/cicids2017/tshark_friday.tsv`) is included in the artefact. The
8.2 GB capture and the 383 MB trimmed copy are not included, because of their size. The capture is
available from the dataset's publisher.
