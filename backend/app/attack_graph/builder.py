"""Attack graph reconstruction.

Builds a deterministic node/edge graph from the incident's correlated
events and MITRE mappings. The frontend renders this with React Flow.

Industry-grade enrichment:
- Every node/edge is risk-weighted (severity + anomaly signal + asset
  criticality) and carries event counts + first/last seen timestamps so the
  frontend can render heat, scrub time, and explain the graph.
- Lateral-movement edges (same user/device across two assets) are explicit.
- Graph statistics (density, depth, node/edge type distribution) and the
  highest-risk critical path from the attacker to the crown-jewel asset are
  computed and returned.
"""
import heapq
import logging
from typing import Any, Dict, List, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.utils import to_uuid

from app.models.security import Asset, Incident, IncidentEvent, SecurityEvent
from app.services.mitre_service import list_incident_mappings

logger = logging.getLogger(__name__)

NODE_COLORS = {
    "ATTACKER": "#f87171",
    "IP": "#fb923c",
    "USER": "#22d3ee",
    "DEVICE": "#a78bfa",
    "PROCESS": "#fbbf24",
    "SERVER": "#60a5fa",
    "DATABASE": "#f472b6",
    "DOMAIN": "#34d399",
    "MALWARE": "#ef4444",
    "TECHNIQUE": "#facc15",
    "ASSET": "#818cf8",
}

SEV_WEIGHT = {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 95}

# Edge types that indicate hostile progression (used for risk + critical path)
HOSTILE_EDGES = {"AUTHENTICATED", "EXECUTED", "ESCALATED", "ACCESSED", "EXFILTRATED", "MOVED_TO"}


def _risk_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _node_risk(events: List[SecurityEvent], node_type: str, extra: float = 0.0) -> float:
    """Risk 0–100 from the events touching a node.

    65% max event severity, 35% mean anomaly signal, plus a node-type bonus
    (asset criticality / technique weight).
    """
    if events:
        sev = max(SEV_WEIGHT.get(e.severity or "LOW", 30) for e in events)
        anom = sum((e.anomaly_score or 0.0) for e in events) / len(events) * 100
        base = 0.65 * sev + 0.35 * min(anom, 100)
    else:
        base = 30.0
    return round(min(100.0, base * 0.8 + extra), 1)


def _event_window(events: List[SecurityEvent]) -> Tuple[str, str]:
    if not events:
        return "", ""
    ts = [e.timestamp for e in events if e.timestamp]
    if not ts:
        return "", ""
    return min(ts).isoformat(), max(ts).isoformat()


def build_attack_graph(db: Session, incident_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Reconstruct (and persist) the enriched attack graph for an incident.

    Returns (nodes, edges) — nodes/edges carry enriched properties.
    """
    uid = to_uuid(incident_id)
    incident = db.scalar(select(Incident).where(Incident.id == uid))
    if incident is None:
        return [], []

    # Collect correlated events
    incident_events = list(db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ).all())
    event_ids = [ie.event_id for ie in incident_events]
    events: List[SecurityEvent] = []
    if event_ids:
        events = list(db.scalars(
            select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
        ).all())

    # Asset criticality lookup (asset digital-twin link)
    asset_crit: Dict[str, int] = {}
    if events:
        for a in db.scalars(select(Asset)).all():
            asset_crit[a.name] = a.criticality or 5

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    def add_node(key: str, node_type: str, label: str, props: Dict[str, Any] = None) -> None:
        if key not in nodes:
            nodes[key] = {
                "node_key": key,
                "node_type": node_type,
                "label": label,
                "properties": props or {},
            }

    def add_edge(src: str, dst: str, edge_type: str, props: Dict[str, Any] = None) -> None:
        if src in nodes and dst in nodes and not any(e["source_key"] == src and e["target_key"] == dst for e in edges):
            edges.append({"source_key": src, "target_key": dst, "edge_type": edge_type, "properties": props or {}})

    # ------------------------------------------------------------------
    # Collect entity -> events (for enrichment)
    # ------------------------------------------------------------------
    def evts(**match) -> List[SecurityEvent]:
        out = []
        for e in events:
            if all(e.__dict__.get(k) == v for k, v in match.items()):
                out.append(e)
        return out

    src_ips = sorted({e.source_ip for e in events if e.source_ip})
    dst_ips = sorted({e.destination_ip for e in events if e.destination_ip})
    users = sorted({e.user_id for e in events if e.user_id})
    devices = sorted({e.device_id for e in events if e.device_id})
    assets = sorted({e.asset_id for e in events if e.asset_id})
    malware = sorted({(e.metadata_ or {}).get("malware") for e in events
                      if e.event_type == "MALWARE_DETECTED" and (e.metadata_ or {}).get("malware")})
    domains = sorted({(e.metadata_ or {}).get("c2_domain") for e in events
                      if (e.metadata_ or {}).get("c2_domain")})

    # 1. Attacker / source IPs
    attacker_key = None
    if src_ips:
        attacker_key = f"ip:{src_ips[0]}"
        el = evts(source_ip=src_ips[0])
        add_node(attacker_key, "IP", src_ips[0], {
            "ip": src_ips[0], "role": "attacker-source",
            "risk_score": _node_risk(el, "IP"), "risk_label": _risk_label(_node_risk(el, "IP")),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        for ip in src_ips[1:]:
            key = f"ip:{ip}"
            el = evts(source_ip=ip)
            add_node(key, "IP", ip, {
                "ip": ip, "role": "source",
                "risk_score": _node_risk(el, "IP"), "risk_label": _risk_label(_node_risk(el, "IP")),
                "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
                "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
            })
            add_edge(attacker_key, key, "CONNECTED_TO", {"event_count": 0, "risk_score": 0.0})
    elif malware:
        attacker_key = f"malware:{malware[0]}"
        add_node(attacker_key, "MALWARE", malware[0], {"malware": malware[0], "risk_score": 80.0,
                                                       "risk_label": "HIGH", "event_count": 1})

    # 2. Users
    user_keys = []
    for u in users:
        key = f"user:{u}"
        el = evts(user_id=u)
        add_node(key, "USER", u, {
            "user": u,
            "risk_score": _node_risk(el, "USER"), "risk_label": _risk_label(_node_risk(el, "USER")),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        user_keys.append(key)
        if attacker_key:
            auth_evts = [e for e in el if e.event_type in ("LOGIN_SUCCESS", "LOGIN_FAILURE")]
            add_edge(attacker_key, key, "AUTHENTICATED", {
                "event_count": len(auth_evts),
                "risk_score": _node_risk(auth_evts, "USER"),
                "severity": max((e.severity for e in auth_evts), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
                **dict(zip(["first_seen", "last_seen"], _event_window(auth_evts))),
            })

    # 3. Devices
    for d in devices:
        key = f"device:{d}"
        el = evts(device_id=d)
        add_node(key, "DEVICE", d, {
            "device": d,
            "risk_score": _node_risk(el, "DEVICE"), "risk_label": _risk_label(_node_risk(el, "DEVICE")),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        for u in users:
            if any(e.user_id == u and e.device_id == d for e in events):
                add_edge(f"user:{u}", key, "CONNECTED_TO", {"event_count": 0, "risk_score": 0.0})

    # 4. Malware / C2 domains
    for m in malware:
        key = f"malware:{m}"
        el = [e for e in events if (e.metadata_ or {}).get("malware") == m]
        add_node(key, "MALWARE", m, {
            "malware": m,
            "risk_score": _node_risk(el, "MALWARE", 10), "risk_label": _risk_label(_node_risk(el, "MALWARE", 10)),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        if attacker_key and f"malware:{m}" != attacker_key:
            add_edge(attacker_key, key, "EXECUTED", {"event_count": 0, "risk_score": 60.0})
        for u in users:
            if any(e.user_id == u and e.event_type == "MALWARE_DETECTED" for e in events):
                add_edge(key, f"user:{u}", "EXECUTED", {"event_count": 1, "risk_score": 70.0})
    for dom in domains:
        key = f"domain:{dom}"
        el = [e for e in events if (e.metadata_ or {}).get("c2_domain") == dom]
        add_node(key, "DOMAIN", dom, {
            "domain": dom,
            "risk_score": _node_risk(el, "DOMAIN", 10), "risk_label": _risk_label(_node_risk(el, "DOMAIN", 10)),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        for m in malware:
            add_edge(f"malware:{m}", key, "CONNECTED_TO", {"event_count": 0, "risk_score": 0.0})

    # 5. Techniques (from MITRE mapping)
    mappings = list_incident_mappings(db, incident_id)
    technique_keys = []
    for m in mappings:
        key = f"technique:{m['technique_id']}"
        extra = 10.0 if (m.get("severity_hint") or "").upper() in ("CRITICAL", "HIGH") else 0.0
        add_node(key, "TECHNIQUE", f"{m['technique_id']} — {m['name']}", {
            "technique_id": m["technique_id"], "tactic": m.get("tactic", ""),
            "risk_score": round(min(100.0, 45 + extra), 1),
            "risk_label": _risk_label(45 + extra),
            "severity": m.get("severity_hint") or "MEDIUM",
            "event_count": 0, "first_seen": "", "last_seen": "",
        })
        technique_keys.append(key)
        for u in users:
            add_edge(f"user:{u}", key, "EXECUTED", {
                "event_count": sum(1 for e in events if e.user_id == u),
                "risk_score": round(min(100.0, 45 + extra), 1),
                "severity": m.get("severity_hint") or "MEDIUM",
            })

    # 6. Assets / servers / databases (risk includes real asset criticality)
    asset_map: Dict[str, str] = {}
    for a in assets:
        key = f"asset:{a}"
        node_type = "DATABASE" if "db" in a.lower() or "database" in a.lower() else "ASSET"
        el = evts(asset_id=a)
        crit = asset_crit.get(a, 5)
        extra = 0.2 * crit * 10
        add_node(key, node_type, a, {
            "asset": a, "criticality": crit,
            "risk_score": _node_risk(el, node_type, extra),
            "risk_label": _risk_label(_node_risk(el, node_type, extra)),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        asset_map[a] = key
        for m in mappings:
            if m["technique_id"] in ("T1005", "T1083", "T1530"):
                add_edge(f"technique:{m['technique_id']}", key, "ACCESSED", {
                    "event_count": len(el), "risk_score": _node_risk(el, node_type, extra),
                    "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
                })

    # Assets must always be reachable: connect the acting user (or attacker)
    # directly when no technique mapping linked them yet.
    for a, key in asset_map.items():
        if not any(e["target_key"] == key for e in edges):
            anchor = user_keys[0] if user_keys else attacker_key
            if anchor:
                el = evts(asset_id=a)
                add_edge(anchor, key, "ACCESSED", {
                    "event_count": len(el), "risk_score": _node_risk(el, "ASSET", 0.2 * asset_crit.get(a, 5) * 10),
                    "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
                    **dict(zip(["first_seen", "last_seen"], _event_window(el))),
                    "via": "direct-activity",
                })

    # 7. Lateral movement: same user or device acting across two assets
    if len(assets) >= 2:
        for i, a1 in enumerate(assets):
            for a2 in assets[i + 1:]:
                shared_user = any(
                    e1.user_id and e1.user_id == e2.user_id for e1 in events if e1.asset_id == a1
                    for e2 in events if e2.asset_id == a2
                )
                shared_device = any(
                    e1.device_id and e1.device_id == e2.device_id for e1 in events if e1.asset_id == a1
                    for e2 in events if e2.asset_id == a2
                )
                if shared_user or shared_device:
                    el = [e for e in events if e.asset_id in (a1, a2)]
                    add_edge(asset_map[a1], asset_map[a2], "MOVED_TO", {
                        "event_count": len(el),
                        "risk_score": round(_node_risk(el, "ASSET") * 0.8, 1),
                        "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
                        **dict(zip(["first_seen", "last_seen"], _event_window(el))),
                        "via": "shared-user" if shared_user else "shared-device",
                    })

    # 8. Destination IPs (exfiltration targets)
    for ip in dst_ips:
        key = f"dst:{ip}"
        el = evts(destination_ip=ip)
        add_node(key, "IP", ip, {
            "ip": ip, "role": "destination",
            "risk_score": _node_risk(el, "IP"), "risk_label": _risk_label(_node_risk(el, "IP")),
            "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            "event_count": len(el), **dict(zip(["first_seen", "last_seen"], _event_window(el))),
        })
        exfil = any(e.event_type == "DATA_EXFILTRATION" and e.destination_ip == ip for e in events)
        edge_type = "EXFILTRATED" if exfil else "CONNECTED_TO"
        anchor = asset_map.get(assets[0]) if assets else (user_keys[0] if user_keys else attacker_key)
        if anchor:
            add_edge(anchor, key, edge_type, {
                "event_count": len(el), "risk_score": _node_risk(el, "IP", 10),
                "severity": max((e.severity for e in el), default="LOW", key=lambda s: SEV_WEIGHT.get(s, 0)),
            })

    # 9. Privilege escalation → technique link
    if any(e.event_type == "PRIVILEGE_ESCALATION" for e in events) and user_keys:
        pe = [e for e in events if e.event_type == "PRIVILEGE_ESCALATION"]
        add_edge(f"user:{user_keys[0]}", "technique:T1548", "ESCALATED", {
            "event_count": len(pe), "risk_score": _node_risk(pe, "USER", 10),
            "severity": max((e.severity for e in pe), default="HIGH", key=lambda s: SEV_WEIGHT.get(s, 0)),
        })

    # Persist (properties include risk / timestamps / counts)
    persist_graph(db, uid, nodes, edges)

    layout = _layout(nodes, edges)
    enriched_nodes = [{
        "node_key": k, "node_type": v["node_type"], "label": v["label"],
        "properties": {**v["properties"], **layout.get(k, {})},
    } for k, v in nodes.items()]
    return enriched_nodes, edges


def build_attack_graph_full(db: Session, incident_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """Enriched graph + statistics + critical path (used by the API)."""
    nodes, edges = build_attack_graph(db, incident_id)
    stats = _graph_stats(nodes, edges)
    critical_path = _critical_path(nodes, edges)

    # Attack-flow analysis from the correlated event count + entity breakdown
    uid = to_uuid(incident_id)
    events_analyzed = db.scalar(
        select(func.count()).select_from(IncidentEvent).where(IncidentEvent.incident_id == uid)
    ) or 0
    stats["events_analyzed"] = events_analyzed
    stats["attackers"] = sum(
        1 for n in nodes
        if n["node_type"] == "IP" and n["properties"].get("role") in ("attacker-source", "source")
    )
    stats["users"] = stats.get("node_types", {}).get("USER", 0)
    stats["techniques"] = stats.get("node_types", {}).get("TECHNIQUE", 0)
    stats["assets"] = (
        stats.get("node_types", {}).get("ASSET", 0)
        + stats.get("node_types", {}).get("DATABASE", 0)
        + stats.get("node_types", {}).get("SERVER", 0)
    )
    return nodes, edges, stats, critical_path


def _graph_stats(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    v = len(nodes)
    e = len(edges)
    density = round(2 * e / (v * (v - 1)), 4) if v > 1 else 0.0

    node_types: Dict[str, int] = {}
    for n in nodes:
        node_types[n["node_type"]] = node_types.get(n["node_type"], 0) + 1
    edge_types: Dict[str, int] = {}
    for ed in edges:
        edge_types[ed["edge_type"]] = edge_types.get(ed["edge_type"], 0) + 1

    # Crown jewel: highest-risk asset-like node
    crown = None
    crown_risk = 0.0
    for n in nodes:
        if n["node_type"] in ("ASSET", "DATABASE", "SERVER"):
            risk = n["properties"].get("risk_score") or 0.0
            if risk > crown_risk:
                crown, crown_risk = n["node_key"], risk

    # BFS depth from the attacker node
    roots = [n["node_key"] for n in nodes if n["node_key"].startswith("ip:") or n["node_key"].startswith("malware:")]
    depth = 0
    if roots:
        adj: Dict[str, List[str]] = {}
        for ed in edges:
            adj.setdefault(ed["source_key"], []).append(ed["target_key"])
        for root in roots:
            seen = {root}
            frontier = [root]
            d = 0
            while frontier:
                nxt = []
                for nd in frontier:
                    for t in adj.get(nd, []):
                        if t not in seen:
                            seen.add(t)
                            nxt.append(t)
                if nxt:
                    d += 1
                frontier = nxt
            depth = max(depth, d)

    return {
        "total_nodes": v,
        "total_edges": e,
        "node_types": node_types,
        "edge_types": edge_types,
        "density": density,
        "max_depth": depth,
        "crown_jewel": crown,
        "crown_jewel_risk": round(crown_risk, 1) if crown else None,
    }


def _critical_path(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Highest cumulative-risk path from the attacker to the crown jewel.

    Dijkstra maximizing (node risk + edge risk) along hostile progression
    edges. Returns the node keys, labels, edge types, and total risk.
    """
    node_keys = [n["node_key"] for n in nodes]
    if not node_keys:
        return {"nodes": [], "node_labels": [], "edge_types": [], "total_risk": 0.0}

    roots = [k for k in node_keys if k.startswith("ip:") or k.startswith("malware:")]
    target = None
    target_risk = -1.0
    for n in nodes:
        if n["node_type"] in ("ASSET", "DATABASE", "SERVER"):
            r = n["properties"].get("risk_score") or 0.0
            if r > target_risk:
                target, target_risk = n["node_key"], r
    if target is None:
        target = node_keys[-1]

    node_risk = {n["node_key"]: (n["properties"].get("risk_score") or 0.0) for n in nodes}
    edge_map: Dict[str, List[Tuple[str, str, float, str]]] = {}
    for ed in edges:
        # Traverse every real relationship; hostile progression edges are
        # weighted higher so they are preferred when both routes exist.
        er = (ed["properties"].get("risk_score") or 0.0)
        if ed["edge_type"] in HOSTILE_EDGES:
            er += 10.0
        edge_map.setdefault(ed["source_key"], []).append(
            (ed["target_key"], er, ed["edge_type"])
        )

    best: Dict[str, float] = {}
    prev: Dict[str, Tuple[str, str]] = {}  # node -> (prev_node, edge_type)
    pq: List[Tuple[float, str]] = []
    for r in roots:
        best[r] = node_risk.get(r, 0.0)
        heapq.heappush(pq, (-best[r], r))
    while pq:
        neg, cur = heapq.heappop(pq)
        cur_score = -neg
        if cur_score < best.get(cur, 0.0):
            continue
        for nxt, er, etype in edge_map.get(cur, []):
            cand = cur_score + node_risk.get(nxt, 0.0) + er
            if cand > best.get(nxt, -1.0):
                best[nxt] = cand
                prev[nxt] = (cur, etype)
                heapq.heappush(pq, (-cand, nxt))

    # Reconstruct path to target (best achievable from any root)
    if target not in best:
        return {"nodes": [], "node_labels": [], "edge_types": [], "total_risk": 0.0}
    path_keys = [target]
    edge_types = []
    cur = target
    while cur in prev:
        pcur, etype = prev[cur]
        path_keys.append(pcur)
        edge_types.append(etype)
        cur = pcur
    path_keys.reverse()
    edge_types.reverse()
    labels = []
    key_to_label = {n["node_key"]: n["label"] for n in nodes}
    for k in path_keys:
        labels.append(key_to_label.get(k, k))
    return {
        "nodes": path_keys,
        "node_labels": labels,
        "edge_types": edge_types,
        "total_risk": round(best.get(target, 0.0), 1),
    }


def persist_graph(db: Session, incident_id: str, nodes: Dict[str, Dict[str, Any]], edges: List[Dict[str, Any]]) -> None:
    from app.models.investigation import AttackEdge, AttackNode

    for old in list(db.scalars(select(AttackNode).where(AttackNode.incident_id == incident_id)).all()):
        db.delete(old)
    for old in list(db.scalars(select(AttackEdge).where(AttackEdge.incident_id == incident_id)).all()):
        db.delete(old)
    db.flush()
    for key, n in nodes.items():
        db.add(AttackNode(incident_id=incident_id, node_key=key, node_type=n["node_type"],
                          label=n["label"], properties=n["properties"]))
    for e in edges:
        db.add(AttackEdge(incident_id=incident_id, source_key=e["source_key"], target_key=e["target_key"],
                          edge_type=e["edge_type"], properties=e["properties"]))
    db.commit()


def _layout(nodes: Dict[str, Dict[str, Any]], edges: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    """Layered attack-flow layout.

    Columns are BFS depth from the attacker(s) (attacker left, crown jewel
    right); nodes within a column are stacked vertically in a deterministic
    type-then-label order and the column is centered. This keeps the kill
    chain readable and avoids the column-overlap of the old type-fixed layout.
    """
    adj: Dict[str, List[str]] = {}
    for e in edges:
        adj.setdefault(e["source_key"], []).append(e["target_key"])

    roots = [k for k in nodes if k.startswith("ip:") or k.startswith("malware:")]
    level: Dict[str, int] = {}
    for r in roots:
        level[r] = 0
    frontier = list(roots)
    depth = 0
    while frontier:
        nxt: List[str] = []
        for nd in frontier:
            for t in adj.get(nd, []):
                if t not in level and t in nodes:
                    level[t] = depth + 1
                    nxt.append(t)
        frontier = nxt
        depth += 1
    # Isolated / unattached nodes go one column past the deepest level
    for k in nodes:
        if k not in level:
            level[k] = depth + 1

    order = {"IP": 0, "MALWARE": 1, "USER": 2, "DEVICE": 3, "TECHNIQUE": 4,
             "DOMAIN": 5, "ASSET": 6, "DATABASE": 7, "SERVER": 8, "PROCESS": 9}
    by_level: Dict[int, List[str]] = {}
    for k in nodes:
        by_level.setdefault(level[k], []).append(k)
    for lv, keys in by_level.items():
        keys.sort(key=lambda k: (order.get(nodes[k]["node_type"], 99), nodes[k]["label"]))

    pos: Dict[str, Dict[str, float]] = {}
    for lv, keys in by_level.items():
        x = 60.0 + lv * 210.0
        n = len(keys)
        for i, k in enumerate(keys):
            pos[k] = {"x": x, "y": 40.0 + i * 120.0 - (n - 1) * 60.0}
    return pos

