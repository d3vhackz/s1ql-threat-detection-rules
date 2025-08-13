# Persistence / Evasion - Registry Key Create or Delete

## Overview

Malware isn't just about planting artifacts - it's also about removing them. Advanced threats often create or delete registry keys to hide tracks, disable logging, or remove persistence after achieving their goal.

This rule catches creation or deletion of registry keys in sensitive areas like Run, RunOnce, or Security Providers.

## Real World Example

**APT41** (a Chinese state-sponsored hacker group) exploited a Citrix vulnerability and created and modified startup files for persistence. They added a registry key in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost` to establish persistence for Cobalt Strike.

**Reference**: [Google Cloud Threat Intelligence - APT41 Global Intrusion Campaign](https://cloud.google.com/blog/topics/threat-intelligence/apt41-initiates-global-intrusion-campaign-using-multiple-exploits/)

## Detection Rule

```json
{
  "ruleName": "Persistence / Evasion - Registry Key Create or Delete",
  "description": "Detect creation or deletion of critical registry keys tied to system startup or security tools.",
  "severity": "Medium",
  "enabled": true,
  "query": "(EventType = 'RegistryKeyCreate' OR EventType = 'RegistryKeyDelete') AND (RegistryPath CONTAINS '\\Run' OR RegistryPath CONTAINS '\\RunOnce' OR RegistryPath CONTAINS '\\Security Providers')",
  "tactics": ["Persistence", "Defense Evasion"],
  "techniques": ["T1547.001", "T1112"]
}
```

## MITRE ATT&CK Mapping

- **Tactics**: Persistence, Defense Evasion
- **Techniques**: 
  - [T1547.001](https://attack.mitre.org/techniques/T1547/001/) - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
  - [T1112](https://attack.mitre.org/techniques/T1112/) - Modify Registry

## Tuning Recommendations

- **Exclude legitimate processes**: Filter out known cleanup utilities and Windows update processes
- **Environment considerations**: Limit monitoring to devices where registry modification activity is typically rare
- **Baseline establishment**: Monitor normal registry activity patterns before deploying in production
- **False positive reduction**: Consider time-based filtering for maintenance windows

## Testing

To test this rule, you can simulate registry key creation/deletion in monitored paths:

```powershell
# Test registry key creation (remove immediately after testing)
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "TestKey" -Force
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestKey" -Force
```

**⚠️ Warning**: Only test in controlled environments with proper authorization.

## Additional Context

This detection focuses on high-value registry locations commonly abused by malware for:
- **Persistence mechanisms**: Ensuring malware survives reboots
- **Security tool evasion**: Disabling or modifying security software configurations
- **Anti-forensics**: Removing traces of malicious activity

Monitor for unusual patterns in registry modification timing, especially during off-hours or in conjunction with other suspicious activities.
