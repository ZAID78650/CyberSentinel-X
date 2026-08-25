"""Model registry — import every model so metadata is complete for Alembic."""
from app.models.base import Base, TimestampMixin, UUIDMixin, new_uuid, utcnow
from app.models.user import Device, Role, User, user_roles
from app.models.security import (
    Alert,
    Asset,
    Incident,
    IncidentEvent,
    Notification,
    SecurityEvent,
)
from app.models.intel import (
    IncidentMitreMapping,
    KnowledgeDocument,
    MitreTechnique,
    ThreatIndicator,
    ThreatIntelligenceSource,
)
from app.models.investigation import (
    AIAgentRun,
    ActionLog,
    ApprovalRequest,
    AttackEdge,
    AttackNode,
    IncidentReport,
    Investigation,
    InvestigationEvidence,
    ResponseRecommendation,
    RiskScore,
)
from app.models.feedback import AnalystFeedback, CorrelationSetting
from app.models.forensics import (
    AttackDna,
    AttackPrediction,
    EvidenceRecord,
    LedgerBlock,
)
from app.models.financial import (
    FinancialComplaint,
    FinancialTransaction,
    FinancialAccount,
    WithdrawalZone,
    WithdrawalPrediction,
)

__all__ = [
    "Base",
    "TimestampMixin",
    "UUIDMixin",
    "new_uuid",
    "utcnow",
    "User",
    "Role",
    "user_roles",
    "Device",
    "Asset",
    "SecurityEvent",
    "Alert",
    "Incident",
    "IncidentEvent",
    "Notification",
    "ThreatIndicator",
    "ThreatIntelligenceSource",
    "MitreTechnique",
    "IncidentMitreMapping",
    "KnowledgeDocument",
    "Investigation",
    "InvestigationEvidence",
    "AttackNode",
    "AttackEdge",
    "RiskScore",
    "ResponseRecommendation",
    "ApprovalRequest",
    "IncidentReport",
    "AIAgentRun",
    "ActionLog",
    "EvidenceRecord",
    "LedgerBlock",
    "AttackDna",
    "AttackPrediction",
    "AnalystFeedback",
    "CorrelationSetting",
    "FinancialComplaint",
    "FinancialTransaction",
    "FinancialAccount",
    "WithdrawalZone",
    "WithdrawalPrediction",
]
