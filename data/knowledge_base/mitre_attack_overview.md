# MITRE ATT&CK Framework

MITRE ATT&CK is a globally accessible knowledge base of adversary tactics and
techniques based on real-world observations. It is used by security operations
centers to describe attacker behavior in a common language and to map detections
and responses.

## Tactics (the "why")

Tactics represent the adversary's tactical goal — the reason for performing an
action. Core tactics in the enterprise matrix:

- Reconnaissance: gathering information to plan future operations
- Resource Development: establishing infrastructure and capabilities
- Initial Access: gaining entry into the environment
- Execution: running adversary-controlled code
- Persistence: maintaining a foothold across restarts
- Privilege Escalation: gaining higher-level permissions
- Defense Evasion: avoiding detection
- Credential Access: stealing account names and passwords
- Discovery: learning about the environment
- Lateral Movement: moving through the environment
- Collection: gathering data of interest
- Command and Control: communicating with compromised systems
- Exfiltration: stealing data out of the environment
- Impact: manipulating, interrupting or destroying systems/data

## Techniques (the "how")

Techniques describe *how* an adversary accomplishes a tactical goal, e.g.
T1110 (Brute Force) under Credential Access, or T1078 (Valid Accounts) under
Initial Access. Sub-techniques provide finer granularity (e.g. T1110.001
Password Guessing).

## Procedures (the "what")

Procedures are the specific, implementation-level actions performed by
particular threat actors. They map onto techniques and are often documented in
threat reports.

## Use in CyberSentinel X

- Events and alerts are mapped to techniques with a confidence score.
- Incidents receive a set of mapped techniques that drive the attack graph.
- Detection rules reference techniques in their `detection_reason`.
- Reports list mapped techniques with links to attack.mitre.org.
