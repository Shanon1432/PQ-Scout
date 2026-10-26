"""Emit a CycloneDX Cryptographic Bill of Materials (CBOM)."""
import json, uuid
from datetime import datetime, timezone
from .hndl_score import score_observation


def _protocol_properties(obs):
    """Only include fields that were observed. CycloneDX requires these to be
    strings, so writing null for an unseen value makes the whole CBOM invalid.
    The lab captures never produced that case; the CIC-IDS2017 run did (313
    connections where the ServerHello was not captured), and schema
    validation of that CBOM failed until this was changed."""
    props = {"type": "tls"}
    if obs.negotiated_version:
        props["version"] = obs.negotiated_version
    if obs.selected_cipher:
        props["cipherSuites"] = [{"name": obs.selected_cipher}]
    return props


def _asset_component(obs, score, band, rationale):
    algs = [a for a in (obs.key_exchange, obs.named_group,
                        obs.signature_alg, obs.selected_cipher) if a]
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{obs.asset_id()}",
        "name": obs.selected_cipher or "unknown-suite",
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": _protocol_properties(obs),
        },
        "properties": [
            {"name": "pqscout:asset", "value": obs.asset_id()},
            {"name": "pqscout:serverName", "value": obs.server_name or ""},
            {"name": "pqscout:keyExchange", "value": str(obs.key_exchange)},
            {"name": "pqscout:namedGroup", "value": str(obs.named_group)},
            {"name": "pqscout:signature", "value": str(obs.signature_alg)},
            {"name": "pqscout:algorithms", "value": ", ".join(algs)},
            {"name": "pqscout:hndlScore", "value": str(score)},
            {"name": "pqscout:hndlBand", "value": band},
            {"name": "pqscout:rationale", "value": rationale},
            {"name": "pqscout:captureIncomplete", "value": str(obs.incomplete).lower()},
            {"name": "pqscout:helloRetryRequest", "value": str(obs.hello_retry).lower()},
        ],
    }


def build_cbom(observations):
    """One CBOM component per distinct cryptographic configuration of a
    server asset; `findings` keeps one entry per observed connection.

    The original version wrote one component per connection, all sharing the
    bom-ref "crypto/<ip:port>". With one connection per server (as in every
    lab capture) that was valid, but the CIC-IDS2017 capture has many
    connections to the same server, giving identical components and
    duplicate bom-refs, which CycloneDX rejects (components must be unique).
    """
    groups, findings = {}, []
    for obs in observations:
        score, band, why = score_observation(obs)
        findings.append({"asset": obs.asset_id(), "score": score,
                         "band": band, "rationale": why, "obs": obs})
        key = (obs.asset_id(), obs.negotiated_version, obs.selected_cipher,
               obs.key_exchange, obs.named_group, obs.signature_alg,
               obs.server_name, obs.incomplete, obs.hello_retry, band)
        if key in groups:
            groups[key][4] += 1
        else:
            groups[key] = [obs, score, band, why, 1]
    components, per_asset = [], {}
    for obs, score, band, why, n in groups.values():
        k = per_asset[obs.asset_id()] = per_asset.get(obs.asset_id(), 0) + 1
        comp = _asset_component(obs, score, band, why)
        if k > 1:                                   # keep bom-refs unique
            comp["bom-ref"] += f"#{k}"
        comp["properties"].append({"name": "pqscout:connections", "value": str(n)})
        components.append(comp)
    findings.sort(key=lambda f: f["score"], reverse=True)
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "PQ-Scout", "version": "0.5.0"}],
        },
        "components": components,
    }
    return bom, findings
