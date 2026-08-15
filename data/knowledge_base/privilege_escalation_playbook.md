# Privilege Escalation Playbook

Privilege escalation is the process of gaining higher-level permissions than
the account was originally granted. It is a pivotal step in most intrusions
because it enables access to sensitive systems and data.

## Indicators

- A standard user added to an administrative group or granted admin rights.
- UAC bypass or sudo misuse; setuid binaries exploited.
- New service or scheduled task running as SYSTEM/root.
- Token manipulation, or credential dumping followed by lateral movement.
- Exploitation of a known privilege-escalation CVE (e.g. PrintNightmare).

## Detection guidance

- Compare role/permission changes against a baseline.
- A privilege change immediately following an unusual login is highly
  suspicious.
- Combine with MITRE technique mapping: T1548, T1068, T1136.

## Response actions

1. Revert the privilege change.
2. Disable the affected account and reset credentials.
3. Review all admin account activity for the environment.
4. Patch the underlying vulnerability (CVE-driven).
5. Audit for other accounts changed by the same actor.

## MITRE mapping

- T1548 Abuse Elevation Control Mechanism
- T1068 Exploitation for Privilege Escalation
- T1136 Create Account
- T1098 Account Manipulation
