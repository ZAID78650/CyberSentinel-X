# Brute Force / Credential Stuffing Playbook

Brute force attacks involve systematically guessing credentials. Credential
stuffing reuses credentials leaked from other breaches.

## Indicators

- High volume of failed authentication attempts for one account or from one
  source IP within a short window.
- Failures spread across many accounts from a single IP (password spraying).
- Successful login after a long run of failures (account compromise).
- Unusual login times or source ASNs.
- Lockout events followed by a successful reset flow.

## Detection guidance

- Rule: >= 10 failed logins for the same account within 15 minutes.
- Rule: >= 20 failed logins from the same source IP within 15 minutes.
- Escalate to an incident when a successful login follows a failure burst.

## Response actions

1. Block or rate-limit the offending source IP at the perimeter.
2. Enforce account lockout / step-up authentication.
3. Reset credentials for any account that saw a post-burst success.
4. Review the account for other abuse (email rules, sessions).

## MITRE mapping

- T1110 Brute Force
- T1110.001 Password Guessing
- T1078 Valid Accounts (if a login succeeds)
