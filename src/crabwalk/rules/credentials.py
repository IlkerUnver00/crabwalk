"""Active Directory credential-attack rules: Kerberoasting, DCSync."""

from __future__ import annotations

from collections.abc import Iterator

from ..catalog import SECURITY
from ..hosts import is_anonymous, is_machine_account, remote_ip
from ..sessions import display_user
from .base import Finding, HuntContext, Rule

# RC4-HMAC. Modern service tickets are AES (0x11/0x12); a downgrade to RC4 is
# the classic Kerberoasting signature (crackable offline).
RC4 = "0x17"

# Directory replication extended rights. A DCSync pulls secrets by asking for
# these; only domain controllers have any business requesting them.
REPLICATION_GUIDS = (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
)


class Kerberoasting(Rule):
    """4769 service-ticket request downgraded to RC4 encryption."""

    id = "CW-010"
    title = "Kerberoasting (RC4 service ticket)"
    severity = "high"
    techniques = ("T1558.003",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        for event in ctx.events_for(SECURITY, 4769):
            if str(event.get("TicketEncryptionType")) != RC4:
                continue
            if str(event.get("Status") or "0x0") != "0x0":
                continue  # only successful ticket grants
            service = str(event.get("ServiceName") or "")
            user = str(event.get("TargetUserName") or "")
            # Machine accounts ($) and krbtgt requesting/serving are normal.
            if is_machine_account(service) or service.lower() == "krbtgt":
                continue
            if is_machine_account(user):
                continue
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=(
                    f"RC4 service ticket for SPN account '{service}' requested by "
                    f"{user} from {event.get('IpAddress') or '?'}"
                ),
                evidence=[event],
                src_ip=remote_ip(event.get("IpAddress")),
            )


class DCSync(Rule):
    """4662 directory replication requested by a non-DC principal."""

    id = "CW-011"
    title = "DCSync (directory replication)"
    severity = "critical"
    techniques = ("T1003.006",)

    def evaluate(self, ctx: HuntContext) -> Iterator[Finding]:
        seen: set[tuple[str, str]] = set()
        for event in ctx.events_for(SECURITY, 4662):
            props = str(event.get("Properties") or "").lower()
            if not any(guid in props for guid in REPLICATION_GUIDS):
                continue
            subject = str(event.get("SubjectUserName") or "")
            # Domain controllers replicate legitimately; they authenticate as
            # machine accounts ($). Anything else asking to replicate is a DCSync.
            if (not subject or is_machine_account(subject)
                    or is_anonymous(subject, event.get("SubjectUserSid"))):
                continue
            user = display_user(event.get("SubjectDomainName"), subject)
            key = (event.computer, user)
            if key in seen:
                continue
            seen.add(key)
            yield self.finding(
                timestamp=event.timestamp,
                host=event.computer,
                user=user,
                summary=(
                    f"Directory replication (DS-Replication-Get-Changes) requested "
                    f"by non-DC principal {user}"
                ),
                evidence=[event],
            )
