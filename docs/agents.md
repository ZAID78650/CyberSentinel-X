# Agents

## Orchestrator (state machine)

`app/agents/orchestrator.py` drives the incident pipeline as a controlled state machine:

```
DETECT → INVESTIGATE → THREAT_INTEL → MITRE → ATTACK_GRAPH
       → RISK → RESPONSE → APPROVAL → SIMULATED_RESPONSE → REPORT
```

Each stage runs in its own DB session, broadcasts its status over WebSocket
(`agent_status` events), and failures are contained — a failing stage is marked
FAILED and the pipeline continues where safe. Agent statuses shown in the UI:
`ONLINE / RUNNING / WAITING / COMPLETED / FAILED`.

## Agent roster

| Agent | Module | Responsibility |
|-------|--------|----------------|
| Detection Agent | `agents/detection_agent.py` | Evaluates ingested events, groups anomalous ones, creates the alert and opens the incident |
| Investigation Agent | `agents/investigation_agent.py` | Correlates entities, histories, intel, RAG context; maps MITRE techniques; builds evidence, timeline, summary, verdict and confidence |
| Threat Intel Agent | `agents/threat_intel_agent.py` | Enriches an incident with indicator intelligence via the adapter |
| Risk Engine | `risk/engine.py` | Computes the explainable risk score |
| Response Agent | `agents/response_agent.py` | Generates recommendations and raises approval requests |
| Report Agent | `reports/generator.py` | Produces HTML + PDF incident reports |

## Allowlisted tools

The Investigation Agent can only call functions registered in
`agents/tools.py` (`TOOL_REGISTRY`). Every call is recorded in `ai_agent_runs.tools_used`:

- `search_security_events` · `get_user_history` · `get_device_history` · `get_asset_information`
- `check_ip_reputation` · `search_threat_intelligence` · `search_knowledge_base`
- `map_mitre_technique` · `create_attack_graph` · `calculate_risk` · `generate_incident_report`

**There is no tool that executes shell commands, runs arbitrary code, accesses
arbitrary files, or touches external systems.** This is enforced by construction —
tools are plain read-mostly database queries.

## LLM abstraction

`agents/llm.py` defines `LLMProvider` with three implementations selected by `LLM_PROVIDER`:

| Provider | When | Behavior |
|----------|------|----------|
| `local` (default) | no API key | Deterministic, evidence-grounded summaries, verdicts and confidence — never hallucinates |
| `openai` | `OPENAI_API_KEY` set | Real LLM reasoning; falls back to local on any error |
| `gemini` | `GEMINI_API_KEY` set | Real LLM reasoning; falls back to local on any error |

Agents call the abstraction for:
- `summarize_investigation` — concise evidence-based summary
- `verdict` — verdict + confidence (e.g. "HIGH-CONFIDENCE MALICIOUS ACTIVITY", 94%)
- `explain_risk` · `describe_recommendation`

**No hidden chain-of-thought is exposed** — only concise operational summaries are stored
(`result_summary`) and shown to analysts.

## Observability

Every agent run persists an `AIAgentRun` record: agent name, run id, incident id, status,
start/end timestamps, tools used, result summary, and error (if any).

## Failure handling

- LLM unavailable → deterministic local summaries
- Threat-intel API unavailable → local synthetic feed
- Vector DB unavailable → RAG returns no context, investigation continues
- Agent failure → run marked FAILED, pipeline continues with remaining stages
