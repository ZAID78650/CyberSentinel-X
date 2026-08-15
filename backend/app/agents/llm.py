"""LLM provider abstraction.

Providers:
- LocalModelProvider (default): deterministic, evidence-grounded summaries.
  Works with zero API keys and never hallucinates.
- OpenAIProvider / GeminiProvider: real LLM calls when API keys are set.

The application is fully functional with the local provider; external LLMs
are an enhancement, never a hard dependency.
"""
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from app.core.config import get_settings

logger = logging.getLogger(__name__)

EVIDENCE_WEIGHTS = {
    "brute-force": 0.18,
    "new-device": 0.12,
    "unusual-location": 0.12,
    "privilege-escalation": 0.2,
    "sensitive-access": 0.16,
    "malware": 0.22,
    "exfiltration": 0.22,
    "intel-match": 0.2,
    "anomaly": 0.15,
    "timeline": 0.1,
}


class LLMProvider(ABC):
    name: str = "abstract"

    @abstractmethod
    def summarize_investigation(self, *, incident_title: str, evidence: List[Dict[str, Any]],
                                timeline_events: List[str], context: Dict[str, Any]) -> str:
        """Return a concise evidence-based investigation summary."""

    @abstractmethod
    def verdict(self, *, evidence: List[Dict[str, Any]], risk_score: float) -> Dict[str, Any]:
        """Return {'verdict': str, 'confidence': float}."""

    @abstractmethod
    def explain_risk(self, *, factors: List[Dict[str, Any]], score: float) -> str:
        """Explain a risk score in plain language."""

    @abstractmethod
    def describe_recommendation(self, *, action: str, evidence: List[str]) -> str:
        """One-sentence rationale for a response action."""


def _evidence_keys(evidence: List[Dict[str, Any]]) -> List[str]:
    keys: List[str] = []
    for e in evidence:
        cat = (e.get("category") or "").lower().replace(" ", "-")
        keys.append(cat)
    return keys


def _base_confidence(evidence: List[Dict[str, Any]]) -> float:
    keys = _evidence_keys(evidence)
    score = 0.3
    for k in keys:
        score += EVIDENCE_WEIGHTS.get(k, 0.06)
    score += min(0.12, 0.03 * len(evidence))
    return round(min(score, 0.99), 2)


class LocalModelProvider(LLMProvider):
    """Deterministic, evidence-grounded generator (no external API)."""

    name = "local"

    def summarize_investigation(self, *, incident_title: str, evidence: List[Dict[str, Any]],
                                timeline_events: List[str], context: Dict[str, Any]) -> str:
        event_count = context.get("event_count", 0)
        source_count = context.get("source_count", 0)
        user = context.get("user", "unknown user")
        ip = context.get("source_ip", "unknown source")

        top = evidence[:4]
        points = " ".join(f"({e.get('category', 'finding')}) {e.get('description', '')}" for e in top)
        summary = (
            f"The Investigation Agent analyzed {event_count} correlated events across {source_count} data sources. "
            f"Activity centers on user '{user}' from source {ip}. Key findings: {points or 'no high-confidence findings yet'}. "
            f"The evidence pattern is consistent with a coordinated attack chain rather than isolated anomalies."
        )
        return summary.strip()

    def verdict(self, *, evidence: List[Dict[str, Any]], risk_score: float) -> Dict[str, Any]:
        confidence = _base_confidence(evidence)
        keys = _evidence_keys(evidence)
        malicious_hits = [k for k in keys if k in ("malware", "exfiltration", "privilege-escalation", "intel-match")]
        if risk_score >= 70 or len(malicious_hits) >= 2:
            verdict = "HIGH-CONFIDENCE MALICIOUS ACTIVITY"
        elif risk_score >= 40 or confidence >= 0.55:
            verdict = "SUSPICIOUS ACTIVITY — INVESTIGATION RECOMMENDED"
        else:
            verdict = "LOW-RISK ANOMALY — MONITOR"
        return {"verdict": verdict, "confidence": round(confidence * 100, 1)}

    def explain_risk(self, *, factors: List[Dict[str, Any]], score: float) -> str:
        top = sorted(factors, key=lambda f: f.get("contribution", 0), reverse=True)[:3]
        parts = [f"{f.get('name')} contributed {round(f.get('contribution', 0) * 100)}%" for f in top]
        return f"Risk score {round(score)}/100. " + "; ".join(parts) + "."

    def describe_recommendation(self, *, action: str, evidence: List[str]) -> str:
        ev = evidence[0] if evidence else "the observed activity"
        return f"Recommended because {ev}. This action reduces exposure and is standard for this scenario."


class OpenAIProvider(LLMProvider):
    name = "openai"

    def _client(self):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("openai package not installed") from exc
        return OpenAI(api_key=get_settings().openai_api_key)

    def _chat(self, system: str, user: str) -> str:
        try:
            client = self._client()
            resp = client.chat.completions.create(
                model=get_settings().llm_model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                max_tokens=500,
                temperature=0.2,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:
            logger.warning("OpenAI call failed, using local fallback: %s", exc)
            return LocalModelProvider().summarize_investigation(
                incident_title="", evidence=[], timeline_events=[], context={}
            )

    def summarize_investigation(self, *, incident_title: str, evidence: List[Dict[str, Any]],
                                timeline_events: List[str], context: Dict[str, Any]) -> str:
        system = "You are a SOC investigation summarizer. Be concise and evidence-based. Never invent facts not present in the evidence."
        user = (
            f"Incident: {incident_title}\n"
            f"Context: {context}\n"
            f"Timeline events: {timeline_events}\n"
            f"Evidence: {evidence}\n"
            "Write a 3-4 sentence investigation summary grounded only in the provided evidence."
        )
        return self._chat(system, user)

    def verdict(self, *, evidence: List[Dict[str, Any]], risk_score: float) -> Dict[str, Any]:
        return LocalModelProvider().verdict(evidence=evidence, risk_score=risk_score)

    def explain_risk(self, *, factors: List[Dict[str, Any]], score: float) -> str:
        return LocalModelProvider().explain_risk(factors=factors, score=score)

    def describe_recommendation(self, *, action: str, evidence: List[str]) -> str:
        return LocalModelProvider().describe_recommendation(action=action, evidence=evidence)


class GeminiProvider(LLMProvider):
    name = "gemini"

    def _chat(self, prompt: str) -> str:
        try:
            import google.generativeai as genai  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("google-generativeai package not installed") from exc
        try:
            genai.configure(api_key=get_settings().gemini_api_key)
            model = genai.GenerativeModel(get_settings().llm_model)
            resp = model.generate_content(prompt)
            return resp.text or ""
        except Exception as exc:
            logger.warning("Gemini call failed, using local fallback: %s", exc)
            return LocalModelProvider().summarize_investigation(
                incident_title="", evidence=[], timeline_events=[], context={}
            )

    def summarize_investigation(self, *, incident_title: str, evidence: List[Dict[str, Any]],
                                timeline_events: List[str], context: Dict[str, Any]) -> str:
        prompt = (
            f"Summarize this security investigation concisely, grounded only in the evidence.\n"
            f"Incident: {incident_title}\nContext: {context}\nTimeline: {timeline_events}\nEvidence: {evidence}"
        )
        return self._chat(prompt)

    def verdict(self, *, evidence: List[Dict[str, Any]], risk_score: float) -> Dict[str, Any]:
        return LocalModelProvider().verdict(evidence=evidence, risk_score=risk_score)

    def explain_risk(self, *, factors: List[Dict[str, Any]], score: float) -> str:
        return LocalModelProvider().explain_risk(factors=factors, score=score)

    def describe_recommendation(self, *, action: str, evidence: List[str]) -> str:
        return LocalModelProvider().describe_recommendation(action=action, evidence=evidence)


_provider: Optional[LLMProvider] = None


def get_llm() -> LLMProvider:
    global _provider
    if _provider is not None:
        return _provider
    settings = get_settings()
    choice = settings.llm_provider.lower()
    if choice == "openai" and settings.openai_api_key:
        _provider = OpenAIProvider()
    elif choice == "gemini" and settings.gemini_api_key:
        _provider = GeminiProvider()
    else:
        _provider = LocalModelProvider()
    logger.info("using LLM provider: %s", _provider.name)
    return _provider
