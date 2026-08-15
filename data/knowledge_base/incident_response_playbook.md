# Incident Response Playbook (Generic)

This playbook defines the standard operating procedure for responding to a
confirmed or suspected security incident. It follows the NIST 800-61 lifecycle:
Preparation, Detection & Analysis, Containment, Eradication, Recovery, and
Post-Incident Activity.

## 1. Preparation

- Maintain an up-to-date asset inventory with criticality ratings.
- Ensure credentials for break-glass accounts and incident tools are available.
- Document communication channels and escalation contacts.
- Back up critical systems and validate restore procedures.

## 2. Detection & Analysis

- Preserve evidence: record timestamps, capture logs, take memory/disk images.
- Correlate the alert with surrounding events to determine scope.
- Identify affected users, devices, IPs, and data.
- Map activity to MITRE ATT&CK techniques.
- Assign a severity and risk score; open an incident record.

## 3. Containment

- Short-term: isolate affected endpoints, disable compromised accounts,
  block malicious IPs, revoke sessions.
- Long-term: apply patches, reset credentials, enforce MFA.
- Document every action taken in the audit log.

## 4. Eradication

- Remove malware, revoke attacker access, close backdoors.
- Verify the attacker no longer has access (re-check sessions, persistence).

## 5. Recovery

- Restore systems from known-good backups.
- Monitor restored systems for re-infection or continued compromise.

## 6. Post-Incident Activity

- Generate the incident report with timeline, evidence, and lessons learned.
- Update detection rules and playbooks based on findings.
- Review whether any regulatory reporting obligations apply.

## Analyst guidance

- Never destroy evidence during containment.
- Every response action must be traceable to a human decision or an approved
  automated action.
- High-impact actions (blocking, isolation, credential resets) require human
  approval before execution.
