# Incident Report – Multiple Failed RDP Login Attempts

## Incident Summary

**Incident:** Multiple Failed RDP Login Attempts  
**Severity:** Medium  
**Detection:** Custom Microsoft Sentinel scheduled analytics rule  
**MITRE ATT&CK:** T1110 – Brute Force  
**Affected host:** SOC-Windows-01  
**Affected account:** SOC-Windows-01\socadmin  

## Detection Logic

The analytics rule detects three or more failed authentication attempts grouped by source IP, account, computer, and logon type.

```kusto
SecurityEvent
| where EventID == 4625
| where LogonType in (3, 10)
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Account, Computer, LogonType
| where FailedAttempts >= 3
```

## Investigation Actions

1. Reviewed the Sentinel incident and associated alert.
2. Examined the mapped IP, account, and host entities.
3. Reviewed Event ID 4625 failed authentication events.
4. Correlated Event ID 4624 successful authentication activity.
5. Reviewed source-IP context in Microsoft Defender.
6. Checked Defender Threat Intelligence reputation.
7. Pivoted into Advanced Hunting to search for additional activity.
8. Reviewed authentication packages and logon processes.
9. Summarized successful and failed authentication activity over the investigation window.

## Findings

- Repeated failed authentication events were confirmed.
- The activity targeted the local `socadmin` account on `SOC-Windows-01`.
- The detection initially assumed LogonType 10, but the generated failures were observed as LogonType 3.
- The analytics logic was updated to account for observed telemetry.
- Successful authentication events were also observed and correlated separately.
- Defender Threat Intelligence did not classify the source IP as known malicious.
- No additional malicious activity was identified in the available Advanced Hunting telemetry.
- The activity was generated intentionally as part of authorized security testing.

## Analyst Determination

The alert was a valid detection of suspicious authentication behavior, but the underlying activity was authorized.

**Final classification:** Informational, expected activity – Security testing

## Response

No containment or remediation was required because the activity was part of the approved SOC lab.

## Lessons Learned

- Detection logic should be validated against actual telemetry rather than assumed event semantics.
- Entity mapping significantly improves incident context and investigation efficiency.
- Incident filters can hide valid detections and should be checked during troubleshooting.
- Authentication investigations require correlation between failed and successful logons, source IPs, logon types, and authentication mechanisms.
