"""Investigation, attack graph, and risk routes."""
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.attack_graph.builder import build_attack_graph_full
from app.attack_graph.validate import validate_attack_graph
from app.core.database import get_db
from app.models.investigation import Investigation, InvestigationEvidence
from app.models.user import User
from app.risk.engine import get_latest_risk
from app.schemas.investigation import (
    AttackGraphOut,
    AttackNodeOut,
    AttackEdgeOut,
    CriticalPath,
    GraphStats,
    InvestigationDetail,
    InvestigationOut,
    RiskOut,
)
from app.services.mitre_service import list_incident_mappings

router = APIRouter(tags=["investigation"])


@router.get("/api/investigations/{incident_id}", response_model=InvestigationDetail)
def get_investigation(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    inv = db.scalar(
        select(Investigation).where(Investigation.incident_id == incident_id)
        .order_by(Investigation.created_at.desc())
    )
    if inv is None:
        raise HTTPException(status_code=404, detail="No investigation found for this incident")
    evidence = list(db.scalars(
        select(InvestigationEvidence).where(InvestigationEvidence.investigation_id == inv.id)
    ).all())
    mappings = list_incident_mappings(db, str(incident_id))
    return InvestigationDetail(
        investigation=InvestigationOut.model_validate(inv),
        evidence=[
            {"category": e.category, "description": e.description, "source": e.source, "detail": e.detail}
            for e in evidence
        ],
        mitre_mappings=mappings,
    )


@router.get("/api/attack-graph/{incident_id}", response_model=AttackGraphOut)
def get_attack_graph(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    nodes, edges, stats, critical_path = build_attack_graph_full(db, str(incident_id))
    return AttackGraphOut(
        incident_id=incident_id,
        nodes=[AttackNodeOut(id=n["node_key"], node_key=n["node_key"], node_type=n["node_type"],
                             label=n["label"], properties=n["properties"]) for n in nodes],
        edges=[AttackEdgeOut(id=f"{e['source_key']}->{e['target_key']}", source_key=e["source_key"],
                             target_key=e["target_key"], edge_type=e["edge_type"], properties=e["properties"])
               for e in edges],
        stats=GraphStats(**stats) if stats else None,
        critical_path=CriticalPath(**critical_path) if critical_path else None,
    )


@router.post("/api/attack-graph/{incident_id}/validate")
def validate_graph(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    """Industry-standard accuracy audit of the reconstructed attack graph."""
    return validate_attack_graph(db, str(incident_id))


@router.get("/api/risk/{incident_id}", response_model=RiskOut)
def get_risk(incident_id: UUID, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    risk = get_latest_risk(db, str(incident_id))
    factors = risk.get("factors", [])
    return RiskOut(
        incident_id=incident_id,
        score=risk["score"],
        severity_label=risk["severity_label"],
        confidence=risk["confidence"],
        factors=[f for f in factors],
        reason=risk.get("reason", ""),
        computed_at=risk.get("computed_at"),
    )
