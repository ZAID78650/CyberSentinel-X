# Account Takeover Playbook

Account takeover (ATO) occurs when an adversary gains control of a legitimate
user account using stolen credentials, session tokens, or MFA bypass.

## Indicators of account takeover

- Multiple failed logins followed by a successful login from a new IP.
- Successful login from a new device or unusual geolocation.
- Login from a location inconsistent with the user's travel pattern.
- Privilege escalation shortly after login.
- Unusual database or sensitive-resource access after login.
- Password changes, new MFA device enrollments, or email forwarding rules.

## Detection guidance

- Flag successful logins that follow a burst of failures (password spraying).
- Flag logins from devices/IPs with no prior history for the account.
- Correlate post-login activity: privilege changes + sensitive access together
  strongly indicate compromise.

## Response actions

1. Revoke active sessions for the account.
2. Force password reset and re-enrollment of MFA.
3. Notify the account owner and confirm legitimacy of recent logins.
4. Review recent account activity (email rules, API keys, role changes).
5. If sensitive data was accessed, assess data exposure and notify stakeholders.

## MITRE mapping

- T1078 Valid Accounts (initial access)
- T1110 Brute Force (password spraying precursor)
- T1548 Abuse Elevation Control Mechanism (post-compromise escalation)
