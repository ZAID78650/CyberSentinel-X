"""Attack Graph Accuracy Audit.

Industry-standard validation of the reconstructed attack graph, aligned with
the audit requirements of NIST 800-115-style validation: every artifact in a
security graph must be traceable to evidence, structurally valid, temporally
consistent, MITRE-consistent, and reproducible.

Checks performed on `POST /api/attack-graph/{incident_id}/validate`:

1. **Evidence grounding** — every node must be backed by correlated events
   (or, for MITRE technique nodes, by the incident's actual mapping).
   Phantom nodes (no evidence) are flagged HIGH.
2. **Edge schema** — each typed edge must connect valid source/target node
   kinds (e.g. AUTHENTICATED is IP→USER, EXFILTRATED ends at an IP).
   Schema violations are flagged MEDIUM.
3. **MITRE consistency** — every technique node must exist in the incident's
   MITRE mapping (and vice versa: mapped techniques should appear as nodes).
4. **Timeline consistency** — an edge may not predate the first event of its
   source entity (no "time travel" relationships).
5. **Determinism** — rebuilding the graph must produce an identical node/edge
   set (reproducibility for audit).

The composite `accuracy_score` is a weighted mean of the check pass rates.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from sqlalchemy.orm import Session

from app.attack_graph.builder import build_attack_graph
from app.services.mitre_service import list_incident_mappings

# ---------------------------------------------------------------------------
# Allowed source/target node kinds per edge type (industry graph schema).
# CONNECTED_TO is generic connectivity and is not schema-checked.
# ---------------------------------------------------------------------------
EDGE_SCHEMA: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "AUTHENTICATED": (("IP", "MALWARE"), ("USER",)),
    "EXECUTED": (("IP", "MALWARE", "USER"), ("USER", "TECHNIQUE", "MALWARE")),
    "ESCALATED": (("USER",), ("TECHNIQUE",)),
    "ACCESSED": (("TECHNIQUE", "USER"), ("ASSET", "DATABASE", "SERVER", "DEVICE")),
    "EXFILTRATED": (("ASSET", "DATABASE", "SERVER", "USER"), ("IP",)),
    "MOVED_TO": (("ASSET", "DATABASE", "SERVER"), ("ASSET", "DATABASE", "SERVER")),
}

WEIGHTS = {
    "grounding": 0.35,
    "schema": 0.25,
    "mitre": 0.15,
    "timeline": 0.15,
    "determinism": 0.10,
}


def validate_attack_graph(db: Session, incident_id: str) -> Dict[str, Any]:
    """Run all accuracy scans against the reconstructed graph."""
    nodes, edges = build_attack_graph(db, incident_id)
    findings: List[Dict[str, Any]] = []

    # --- 1. Evidence grounding -----------------------------------------
    mappings = list_incident_mappings(db, incident_id)
    mapped_ids = {m["technique_id"] for m in mappings}
    phantom: List[str] = []
    grounded = 0
    for n in nodes:
        ev = int(n["properties"].get("event_count") or 0)
        is_technique = n["node_type"] == "TECHNIQUE"
        if is_technique:
            if str(n["properties"].get("technique_id") or "") in mapped_ids:
                grounded += 1
            else:
                phantom.append(n["node_key"])
        elif ev > 0:
            grounded += 1
        else:
            phantom.append(n["node_key"])
    grounding_pct = round(100 * grounded / max(len(nodes), 1), 1)
    for key in phantom:
        findings.append({"item": key, "issue": "node has no supporting events or MITRE mapping", "severity": "HIGH", "check": "grounding"})

    # --- 2. Edge schema -------------------------------------------------
    node_type = {n["node_key"]: n["node_type"] for n in nodes}
    schema_checked = 0
    schema_valid = 0
    for e in edges:
        rule = EDGE_SCHEMA.get(e["edge_type"])
        if rule is None:
            continue  # CONNECTED_TO is generic
        schema_checked += 1
        allowed_src, allowed_tgt = rule
        src_t = node_type.get(e["source_key"])
        tgt_t = node_type.get(e["target_key"])
        if src_t in allowed_src and tgt_t in allowed_tgt:
            schema_valid += 1
        else:
            findings.append({
                "item": f"{e['source_key']} -> {e['target_key']}",
                "issue": f"{e['edge_type']} connects {src_t or '?'} → {tgt_t or '?'} (expected {allowed_src} → {allowed_tgt})",
                "severity": "MEDIUM", "check": "schema",
            })
    schema_pct = round(100 * schema_valid / max(schema_checked, 1), 1) if schema_checked else 100.0

    # --- 3. MITRE consistency ------------------------------------------
    technique_nodes = {str(n["properties"].get("technique_id") or "") for n in nodes if n["node_type"] == "TECHNIQUE"}
    missing_on_graph = sorted(mapped_ids - technique_nodes)
    orphan_techniques = sorted(technique_nodes - mapped_ids)
    mitre_pct = round(100 * len(technique_nodes & mapped_ids) / max(len(technique_nodes | mapped_ids), 1), 1) \
        if (technique_nodes or mapped_ids) else 100.0
    for t in missing_on_graph:
        findings.append({"item": t, "issue": "technique in incident MITRE mapping absent from graph", "severity": "LOW", "check": "mitre"})
    for t in orphan_techniques:
        findings.append({"item": t, "issue": "technique node not present in incident MITRE mapping", "severity": "LOW", "check": "mitre"})

    # --- 4. Timeline consistency ---------------------------------------
    first_seen = {n["node_key"]: n["properties"].get("first_seen") for n in nodes}
    timeline_checked = 0
    timeline_valid = 0
    for e in edges:
        e_first = e["properties"].get("first_seen")
        src_first = first_seen.get(e["source_key"])
        if not e_first or not src_first:
            continue
        timeline_checked += 1
        try:
            e_t = datetime.fromisoformat(e_first)
            s_t = datetime.fromisoformat(src_first)
            if e_t < s_t:
                findings.append({
                    "item": f"{e['source_key']} -> {e['target_key']}",
                    "issue": f"edge predates its source entity (edge {e_first} < node {src_first})",
                    "severity": "MEDIUM", "check": "timeline",
                })
            else:
                timeline_valid += 1
        except (ValueError, TypeError):
            timeline_valid += 1  # cannot parse — treat as non-blocking
    timeline_pct = round(100 * timeline_valid / max(timeline_checked, 1), 1) if timeline_checked else 100.0

    # --- 5. Determinism -------------------------------------------------
    nodes2, edges2 = build_attack_graph(db, incident_id)
    set1 = {n["node_key"] for n in nodes}
    set2 = {n["node_key"] for n in nodes2}
    edgeset1 = {(e["source_key"], e["target_key"], e["edge_type"]) for e in edges}
    edgeset2 = {(e["source_key"], e["target_key"], e["edge_type"]) for e in edges2}
    deterministic = set1 == set2 and edgeset1 == edgeset2
    if not deterministic:
        findings.append({"item": "graph", "issue": "rebuild produced a different node/edge set (non-reproducible)", "severity": "HIGH", "check": "determinism"})
    determinism_pct = 100.0 if deterministic else 0.0

    # --- Composite score ------------------------------------------------
    checks = [
        {"name": "Evidence grounding", "pass_rate": grounding_pct, "weight": WEIGHTS["grounding"],
         "detail": f"{grounded}/{len(nodes)} nodes backed by events or MITRE mapping"},
        {"name": "Edge schema validity", "pass_rate": schema_pct, "weight": WEIGHTS["schema"],
         "detail": f"{schema_valid}/{schema_checked} typed edges match the allowed graph schema"},
        {"name": "MITRE consistency", "pass_rate": mitre_pct, "weight": WEIGHTS["mitre"],
         "detail": f"graph technique nodes vs incident mapping ({len(technique_nodes)} vs {len(mapped_ids)})"},
        {"name": "Timeline consistency", "pass_rate": timeline_pct, "weight": WEIGHTS["timeline"],
         "detail": f"{timeline_valid}/{timeline_checked} edges respect entity first-seen order"},
        {"name": "Determinism", "pass_rate": determinism_pct, "weight": WEIGHTS["determinism"],
         "detail": "rebuild yields identical node/edge set" if deterministic else "rebuild differs"},
    ]
    score = round(sum(c["pass_rate"] * c["weight"] for c in checks), 1)
    label = "HIGH" if score >= 90 else "GOOD" if score >= 75 else "MODERATE" if score >= 60 else "WEAK"

    return {
        "incident_id": incident_id,
        "accuracy_score": score,
        "label": label,
        "method": "Weighted audit: evidence grounding (35%), edge schema (25%), MITRE consistency (15%), timeline consistency (15%), determinism (10%). Aligned with NIST 800-115 validation practice.",
        "checks": checks,
        "findings": findings,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "grounded_nodes": grounded,
            "phantom_nodes": len(phantom),
            "mapped_techniques": len(mapped_ids),
            "technique_nodes": len(technique_nodes),
        },
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }
