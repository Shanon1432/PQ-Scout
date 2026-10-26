"""Validate PQ-Scout's CBOM output against the official CycloneDX 1.6 schema.

Builds a fresh CBOM from data/multiflow.pcap (so the check covers the
current code, not just a saved file) and validates it with
cyclonedx-python-lib in both normal and strict modes.

One-time setup:  python -m pip install "cyclonedx-python-lib[json-validation]"
Run:             python tests/validate_cbom.py
"""
import io, json, os, sys, contextlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT); sys.path.insert(0, ROOT)
with contextlib.redirect_stderr(io.StringIO()):
    from pqscout.pcap_reader import analyse_pcap
    from pqscout.cbom import build_cbom

try:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator, JsonValidator
except ImportError:
    print('cyclonedx-python-lib is not installed. Run:\n'
          '  python -m pip install "cyclonedx-python-lib[json-validation]"')
    sys.exit(2)


def validate(bom_text):
    out = {}
    for mode, V in (("normal", JsonValidator), ("strict", JsonStrictValidator)):
        err = V(SchemaVersion.V1_6).validate_str(bom_text)
        out[mode] = "VALID" if err is None else "INVALID: " + str(err).split("\n\n")[1].splitlines()[0]
    return out


if __name__ == "__main__":
    bom, findings = build_cbom(analyse_pcap("data/multiflow.pcap"))
    fresh = json.dumps(bom)
    ok = True
    for label, text in (("fresh CBOM from data/multiflow.pcap", fresh),
                        ("saved results/multiflow_cbom.json", open("results/multiflow_cbom.json").read())):
        res = validate(text)
        ok &= all(v == "VALID" for v in res.values())
        print(f"{label}: {len(json.loads(text)['components'])} components  "
              f"normal={res['normal']}  strict={res['strict']}")
    # Optional: the CBOM from the CIC-IDS2017 public-data run (52,536 components).
    # It is only present after tests/cicids_experiment.py has been run.
    cic = "results/cicids2017_cbom.json"
    if os.path.exists(cic):
        text = open(cic).read()
        res = validate(text)
        ok &= all(v == "VALID" for v in res.values())
        print(f"{cic}: {len(json.loads(text)['components']):,} components  "
              f"normal={res['normal']}  strict={res['strict']}")
    print("CycloneDX 1.6 schema validation:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)
