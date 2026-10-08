"""Catalog of event IDs that matter for lateral movement hunting.

Keys are (channel, event_id). Anything outside this catalog is treated as
noise unless the user asks for everything (--all). A few high-volume IDs are
only worth keeping for specific content; CONTENT_FILTERS narrows those.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import NormalizedEvent

SECURITY = "Security"
SYSTEM = "System"
TS_LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
TS_RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
RDP_CORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
POWERSHELL_CLASSIC = "Windows PowerShell"
WINRM = "Microsoft-Windows-WinRM/Operational"
WMI = "Microsoft-Windows-WMI-Activity/Operational"
SYSMON = "Microsoft-Windows-Sysmon/Operational"

CATALOG: dict[tuple[str, int], str] = {
    # --- Authentication & sessions (Security) ---
    (SECURITY, 4624): "Successful logon",
    (SECURITY, 4625): "Failed logon",
    (SECURITY, 4634): "Logoff",
    (SECURITY, 4647): "User-initiated logoff",
    (SECURITY, 4648): "Logon with explicit credentials (runas)",
    (SECURITY, 4672): "Special privileges assigned to new logon",
    (SECURITY, 4768): "Kerberos TGT requested",
    (SECURITY, 4769): "Kerberos service ticket requested",
    (SECURITY, 4771): "Kerberos pre-authentication failed",
    (SECURITY, 4776): "NTLM credential validation",
    (SECURITY, 4662): "Directory service object operation",
    (SECURITY, 4778): "RDP session reconnected",
    (SECURITY, 4779): "RDP session disconnected",
    # --- Execution & persistence footholds (Security) ---
    (SECURITY, 4688): "Process created",
    (SECURITY, 4697): "Service installed",
    (SECURITY, 4698): "Scheduled task created",
    (SECURITY, 4699): "Scheduled task deleted",
    (SECURITY, 4700): "Scheduled task enabled",
    (SECURITY, 4701): "Scheduled task disabled",
    (SECURITY, 4702): "Scheduled task updated",
    (SECURITY, 4720): "User account created",
    (SECURITY, 4726): "User account deleted",
    # --- Shares & anti-forensics (Security) ---
    (SECURITY, 5140): "Network share accessed",
    (SECURITY, 5145): "Network share object access (detailed)",
    (SECURITY, 1102): "Security audit log cleared",
    # --- System channel ---
    (SYSTEM, 7045): "Service installed (Service Control Manager)",
    (SYSTEM, 7036): "Service state change",
    (SYSTEM, 7040): "Service start type changed",
    (SYSTEM, 104): "Event log cleared",
    # --- RDP ---
    (TS_LSM, 21): "RDP session logon",
    (TS_LSM, 22): "RDP shell start",
    (TS_LSM, 23): "RDP session logoff",
    (TS_LSM, 24): "RDP session disconnected",
    (TS_LSM, 25): "RDP session reconnected",
    (TS_RCM, 1149): "RDP network connection accepted",
    (RDP_CORE, 131): "RDP transport connection accepted",
    # --- PowerShell ---
    (POWERSHELL, 4103): "PowerShell module logging",
    (POWERSHELL, 4104): "PowerShell script block logged",
    (POWERSHELL_CLASSIC, 400): "PowerShell engine started",
    (POWERSHELL_CLASSIC, 403): "PowerShell engine stopped",
    # --- WinRM ---
    (WINRM, 6): "WinRM client connection",
    (WINRM, 91): "WinRM shell created (server side)",
    (WINRM, 168): "WinRM session authenticated",
    # --- WMI ---
    (WMI, 5857): "WMI provider started",
    (WMI, 5858): "WMI query error",
    (WMI, 5859): "WMI permanent subscription started",
    (WMI, 5860): "WMI temporary subscription registered",
    (WMI, 5861): "WMI permanent subscription created",
    # --- Sysmon (optional enrichment when present) ---
    (SYSMON, 1): "Sysmon: process created",
    (SYSMON, 3): "Sysmon: network connection",
    (SYSMON, 13): "Sysmon: service ImagePath set",  # narrowed by CONTENT_FILTERS
    (SYSMON, 17): "Sysmon: named pipe created",
    (SYSMON, 18): "Sysmon: named pipe connected",
}

# HKLM\System\CurrentControlSet\Services\<name>\ImagePath (or ControlSet00N):
# the registry footprint of a service install, visible to Sysmon without 7045.
SERVICE_IMAGE_PATH = re.compile(
    r"\\(?:currentcontrolset|controlset\d{3})\\services\\[^\\]+\\imagepath$", re.IGNORECASE
)


def _is_service_image_path(event: NormalizedEvent) -> bool:
    return bool(SERVICE_IMAGE_PATH.search(str(event.get("TargetObject") or "")))


#: Catalog entries that are only kept when the payload matches. Sysmon 13 fires
#: for every registry write on a busy host; only service installs matter here.
CONTENT_FILTERS: dict[tuple[str, int], Callable[[NormalizedEvent], bool]] = {
    (SYSMON, 13): _is_service_image_path,
}


def is_interesting(channel: str, event_id: int) -> bool:
    return (channel, event_id) in CATALOG


def keep_event(event: NormalizedEvent) -> bool:
    """Catalog membership plus any content filter registered for the ID."""
    key = (event.channel, event.event_id)
    if key not in CATALOG:
        return False
    content_filter = CONTENT_FILTERS.get(key)
    return content_filter is None or content_filter(event)


def describe(channel: str, event_id: int) -> str | None:
    return CATALOG.get((channel, event_id))
