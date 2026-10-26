# CIC-IDS2017: feasibility check (not run)

Checked before attempting it, rather than after failing halfway through.

## What was checked

- The official UNB/CIC dataset page confirms raw PCAPs exist, with
  per-day sizes listed: Monday 11.0 GB, Tuesday 11 GB, Wednesday 13 GB,
  Thursday 7.8 GB, Friday 8.3 GB — **~51 GB for the week**.
- The published download portal (`cicresearch.ca/CICDataset/CIC-IDS-2017/`)
  redirects back to the general dataset listing page rather than exposing
  a directly fetchable file index — it did not resolve to an actual
  per-file download link through a direct, scripted request. This matches
  a well-known practical complaint about this dataset: the raw PCAPs are
  not reliably automatable to download; they typically need a browser
  session.
- This session's disk allowance (~30 GB free) could not hold the full
  week even if the portal issue were solved, and would be tight for even
  the smallest single day (Thursday, 7.8 GB) once working space is
  accounted for.
- Separately: this sandbox's own outbound internet access is routed
  through Anthropic's own TLS-terminating egress proxy (confirmed by
  inspecting the certificate chain on a live connection — it presents a
  proxy-issued certificate, not the real site's). That rules out a
  workaround of "capture some real external HTTPS traffic from inside
  this session instead" — anything sniffed here would be a handshake
  with Anthropic's proxy, not a real-world server, so it would not
  actually be real-world validation even though it would look like it.

## Conclusion

A full, faithful CIC-IDS2017 PCAP run is not practical to complete inside
this session: the file is too large for the download+processing budget
available, and the download portal does not resolve to a scriptable
direct link. This is an infrastructure/environment constraint, not a
limitation of PQ-Scout itself, and it should be described that way in the
report rather than silently dropped.

## What was delivered instead

1. **Adversarial stress testing** (`results/stress_findings.md`) — a
   different, and arguably more rigorous, test of real-world robustness:
   deliberately damaged traffic (loss, fragmentation, reordering,
   duplication, late capture) rather than traffic that is merely "from a
   bigger dataset." It found and fixed a real bug.
2. **An active-scan baseline comparison against Nmap**
   (`results/nmap_baseline_findings.md`) — cross-validates PQ-Scout's
   parsing against an independent, trusted tool, and is honest about
   what passive observation does and doesn't give you versus active
   enumeration.

## If more real-world traffic diversity is still wanted

Two options exist, both outside this session:

- **Download a single day's PCAP on your own machine** (not this cloud
  sandbox), where normal browser-based internet access and more disk
  space are both available, then run `pqscout_run.py` against it
  directly — the tool itself doesn't care where a pcap came from. I can
  prepare a short script to pull out just the TLS-handshake-bearing
  packets first (with `tshark`/`editcap`) so the file to actually process
  is a small fraction of the full capture, if you want to go this route.
- **A small public sample set** (e.g. Wireshark's own sample-captures
  page) — genuinely real, non-lab-generated TLS traffic, but at MB scale
  rather than the authority CIC-IDS2017 carries as a named, peer-reviewed
  benchmark dataset. Useful as "does it survive traffic I didn't
  generate" evidence; not a substitute for naming CIC-IDS2017 in the
  methodology if the report claims that dataset specifically.

Neither was done without your steer, since choosing which one changes
what the methodology section can honestly claim.
