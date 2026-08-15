# Data Exfiltration Playbook

Data exfiltration is the unauthorized transfer of data out of the organization.
It is frequently the final stage of a campaign after initial access, privilege
escalation, and collection.

## Indicators

- Large outbound transfers (volume spike) to an external IP/domain.
- Access to sensitive data stores (database, file shares) by accounts with no
  prior history of such access.
- Archiving activity: zip/7z/rar creation near sensitive directories.
- DNS tunneling or data sent over non-standard ports.
- Emails with large attachments to external recipients.

## Detection guidance

- Combine data-access events with outbound transfer spikes.
- A single user accessing many sensitive tables quickly is suspicious.
- Archive-creation + upload is a strong exfiltration sequence.

## Response actions

1. Block outbound traffic to the identified destination.
2. Isolate the source endpoint(s).
3. Revoke the account's access and reset credentials.
4. Determine the sensitivity of data accessed (PII, IP, financial).
5. Initiate regulatory/compliance notification if required.

## MITRE mapping

- T1041 Exfiltration Over C2 Channel
- T1048 Exfiltration Over Alternative Protocol
- T1560 Archive Collected Data
- T1530 Data from Cloud Storage Object
