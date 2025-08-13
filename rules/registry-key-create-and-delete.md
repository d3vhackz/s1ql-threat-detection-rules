Malware isn’t just about planting artifacts - it’s also about removing them.

Advanced threats often create or delete registry keys to hide tracks, disable logging, or remove persistence after achieving their goal.

This rule catches creation or deletion of registry keys in sensitive areas like Run, RunOnce, or Security Providers.

Real World Example: APT41 (a Chinese state-sponsored hacker group) exploited a Citrix vulnerability and created and modified startup files for persistence. They added a registry key in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost to establish persistence for Cobalt Strike.

Read more here: https://cloud.google.com/blog/topics/threat-intelligence/apt41-initiates-global-intrusion-campaign-using-multiple-exploits/

Refinement: Exclude legitimate cleanup utilities and Windows updates. Limit to devices where registry churn is rare.

`json`
{

  "ruleName": "Persistence / Evasion - Registry Key Create or Delete",

  "description": "Detect creation or deletion of critical registry keys tied to system startup or security tools.",

  "severity": "Medium",

  "enabled": true,

  "query": "(EventType = 'RegistryKeyCreate' OR EventType = 'RegistryKeyDelete') AND (RegistryPath CONTAINS '\\Run' OR RegistryPath CONTAINS '\\RunOnce' OR RegistryPath CONTAINS '\\Security Providers')",

  "tactics": ["Persistence", "Defense Evasion"],

  "techniques": ["T1547.001", "T1112"]

}
