"""MITRE ATT&CK technique metadata used by detection rules and reports."""

TECHNIQUES: dict[str, str] = {
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1569.002": "System Services: Service Execution",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1570": "Lateral Tool Transfer",
    "T1078": "Valid Accounts",
    "T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
    "T1003.006": "OS Credential Dumping: DCSync",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)
