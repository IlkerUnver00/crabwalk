# crabwalk detection reference

This reference covers crabwalk's fifteen detection rules: what each one reads, the logic it
runs, how it sets severity, what you can tune, where it is noisy or blind, and which tests
prove it. It describes the code in the commit that contains this version of the file, and
every count below was produced there. The sources are `src/crabwalk/rules/*.py`,
`catalog.py` and `config.py`.

## Scope

crabwalk triages Windows EVTX exports for lateral movement and the activity around it:
remote execution, credential attacks that enable movement, and log clearing. It is not a
general Sigma engine. Several rules correlate across events, channels or hosts rather than
matching single records. Many cataloged IDs feed no rule yet:

- Security: 4625, 4768, 4771, 4776 (failed logons and Kerberos/NTLM authentication, so
  password spraying and brute force produce no finding), 4699-4701, 4720/4726, 5140 and
  4778/4779.
- System 7036/7040, TS-LSM 22/23/24, RCM 1149, RdpCoreTS 131.
- WinRM 6/168, WMI-Activity 5857-5861, PowerShell 4103, Windows PowerShell 400/403.

They appear in `parse` output, never in findings. Security 4634/4647 only set session end
times, and 4648 only adds an outbound edge to the session graph. Sysmon 3 is never a
finding of its own: CW-013 to CW-015 read it to name the other end of a connection.
Sysmon 11 and 13 are kept only for the content the rules use (a file created in a
Startup folder, a service `ImagePath` write), because both fire for every file or
registry write on a busy host.

## How the rules are validated

- **Unit tests** (`tests/test_rules.py`, `tests/test_pipes.py`, `tests/test_dcom.py`,
  `tests/test_remote_files.py`, `tests/test_config.py`) run each rule on synthetic events.
  `pytest tests`: 444 passed.
- **Ground-truth corpus** (`tests/test_corpus.py`) runs over
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0, not
  vendored, under `samples/EVTX-ATTACK-SAMPLES`). `GROUND_TRUTH` has 22 (file, technique,
  rule) entries whose filenames name the technique or the behaviour the rule keys on (CW-006
  is the exception; see its section). `NEGATIVE_TRUTH` has 7 files of *other* attacker
  activity on which a rule must stay silent. Each entry is hunted **one file at a time**,
  and a finding merged under another rule's still counts as that rule firing, both ways.
  `pytest tests/test_corpus.py`: 35 passed.
- **Whole-corpus run.** `crabwalk hunt samples/EVTX-ATTACK-SAMPLES` covers 278 files and
  37,364 records (0 unparsable) and yields 76 findings (4 critical, 56 high, 16 medium),
  after two CW-005 matches are merged into the CW-012 findings that cite them.
  CW-001, CW-002 and CW-010 produce **zero** of them.
- **A second, unseen corpus.** [BENCHMARK.md](BENCHMARK.md#a-second-corpus-the-rules-never-saw)
  runs the rules over
  [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack), which none
  of them was written against, and lists what that run changed here.

**Policy on cross-file correlation.** The whole-corpus run hunts all files together, so
events from separately captured samples of the same host can correlate. Such joins are
reported where they change a result, but only a single-file `GROUND_TRUTH` result counts as
validation.

All paths below are relative to `samples/EVTX-ATTACK-SAMPLES/`.

## Shared building blocks

Several rules use the same derived state, built in `sessions.py` and `rules/base.py`:

- **Logon sessions** are keyed by `(Computer, TargetLogonId)` from Security 4624. A 4672 with
  the same `SubjectLogonId` marks the session privileged. A session is *remote* only when its
  `IpAddress` is a real address: values such as `-`, `127.0.0.1`, `::1` or `localhost`, and
  any loopback address, all count as local.
- **Movement edges** are inbound remote logons: a 4624 with a remote `IpAddress`, or a
  TerminalServices-LocalSessionManager 21/25 with a remote `Address`. A Security 4648 adds an
  outbound "explicit-credentials" edge.
- **Service installs** come from System 7045 (`ServiceName`, `ImagePath`), Security 4697
  (`ServiceName`, `ServiceFileName`) and Sysmon 13 `...\Services\<name>\ImagePath` writes
  (`TargetObject`, `Details`). Copies of one install from different logs (same host and
  service within 10 s) merge into one, preferring 7045. A Sysmon 13 write with no SCM copy
  might just be a reconfigured service. It counts as an install ("credible") only when the
  image looks like remote execution: a command line (`%COMSPEC%`, `cmd /c`, `powershell`,
  `-enc`, `-nop`), a path under `\\127.0.0.1\`, `\ADMIN$\`, `\Windows\Temp\` or
  `\Users\Public\`, or a name or image matching `psexe|paexec|remcom|csexec|winexe`.
- **Machine accounts** are names that end in `$` in any notation (`CORP\PC01$`,
  `PC01$@CORP.LOCAL`).
- **Where a spawned process came from.** WMI, WinRM and DCOM start the requested process in
  the caller's own network logon session. CW-006, CW-007 and CW-013 look up the process's
  session (Sysmon 1 `LogonId`; on a 4688 `TargetLogonId`, else `SubjectLogonId`) and take
  its address and workstation as the finding's source when its 4624 was logged with a
  remote address, as a network logon (type 3 or 8), and the session was alive at the spawn
  (LogonIds repeat across boots). A process in an RDP session (type 10) is a person working
  on this host: a WMI or COM call they make there is local and names no source. CW-015 is
  the one rule that takes an RDP session (type 10 or 7), because `\\tsclient` only exists
  inside one.
- **The other end of a connection.** Sysmon 3 does not put this host's address in a fixed
  field on inbound connections: in the corpus an inbound SMB connection is logged with this
  host as `SourceIp` in one file and as `DestinationIp` in another. `connection_peer()` in
  `rules/base.py` decides which side is this host from the record itself (the side whose
  `SourceHostname`/`DestinationHostname` is this host; the source of a connection the host
  initiated; on an inbound one, the only side on 135, 139, 445, 3389, 5985 or 5986), then
  from the addresses this host is seen using in its other Sysmon 3 records within a day
  (DHCP hands addresses on). When none of that settles it, the connection names no peer.
  The peer's name is the host name Sysmon resolved for that side, when it gives one. The
  rules use only connections in the direction their story needs (the caller connecting in,
  or the RDP client connecting out), and cite a connection only when it names the source.

**Severity levels** are `critical`, `high` and `medium`. No rule emits `low`. Findings that
are identical in (rule, time, host, user, summary) are collapsed.

**One event, one finding.** A finding is merged into another rule's finding that already
tells it: one that cites every record it cites, claims at least its techniques at no lower
severity, adds something (more records, techniques or severity), and names the same host,
the same account (domain-aware: a local `SRV01\x` is not `CORP\x`) and source, or none,
within 10 minutes. The merged finding is listed under the other ("also matched", in full in
the JSON) and still counts as fired for the corpus tests. In practice CW-012 absorbs the
CW-005 drop it credits. It absorbs a CW-001 or CW-004 about the same install or task only
when that finding names no source host or the same one: CW-001 and CW-004 take the
workstation name from the logon, which CW-012 knows only from PsExec stdio pipes, so
usually both stay. Findings that disagree about who did it, or from where, stay separate
(`merge_overlaps()` in `rules/__init__.py`).

**Narrative.** Every rule also sets a short past-tense `action` phrase on its findings
("installed service 'x' (c:\x.exe)"). The attack story (`narrative.py`, `hunt --story`)
is built from those phrases and the attack graph; the README describes it.

**Allowlisting.** An `[[allow]]` entry suppresses a finding only when all of its criteria
match. With `fields`, **every** evidence event of the finding must match one of the entry's
field tables: it must carry all of that table's fields, and each must match its regex.
`[allow.fields]` is one table; `[[allow.fields]]` repeated gives one table per kind of
evidence, so one entry can describe a tool's 5145 opens (`RelativeTargetName`), Sysmon pipe
events (`PipeName`) and install (`ServiceName`) across rules. An entry cannot vouch for
evidence no table describes, and a misspelled field, or one that belongs to another event
type, makes its table match nothing, so the entry fails closed. A finding with no evidence
never matches a `fields` entry. This matters most for CW-012, whose evidence mixes pipe opens,
installs, tasks and drops.

Every table must name at least one field that says what a record is: `ServiceName`,
`ImagePath`, `ServiceFileName`, `RelativeTargetName`, `PipeName`, `TargetObject`, `Details`,
`TaskName`, `TaskContent`, `TaskContentNew`, `CommandLine`, `NewProcessName`, `Hashes`,
`OriginalFileName`, `TargetFilename`, `ScriptBlockText`, `Properties`, `ObjectName`, `Channel`
or `BackupPath`. A Sysmon 3 connection carries none of them: it says who talked to whom, not
what was done. A finding that cites one (CW-013 to CW-015 cite the connection that names
their source) is never matched by a `fields` entry; allowlist it with `users`, `hosts` and
`sources`.
Other fields (who and where, such as `SubjectUserName`, `User`, `IpAddress`; process context
such as `Image`; per-type constants such as `ObjectType` or `AccountName = LocalSystem`)
appear on many kinds of record, so they may only narrow such a table. A table without one is
refused when the file is read, as are an empty table and a regex that accepts any value
(`.*`, `.+`, `\S`). `users`, `hosts` and `sources` express who and where. A misspelled
identifying field leaves its table without one, so it is refused too. A regex that is merely
too broad cannot be detected. Script text, command lines and file names are
attacker-controlled, so the snippets below anchor whole values (`^...$`) and pin what a record
is (name *and* binary, share *and* file), not only a name an attacker can reuse.

When every other criterion holds and the tables cover only part of the evidence, the finding
is kept and `hunt` warns which event types no table describes. It also flags a table whose
fields no record of the data carries together: a misspelled narrowing field, or fields of
different records put in one table. Suppressed findings are still counted and listed. Every
snippet below passes `crabwalk config FILE`.

---

## CW-001: Remote logon followed by service install

**ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares; [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service

**Data sources:** Security 4624 (`TargetLogonId`, `LogonType`, `IpAddress`, `WorkstationName`, `TargetUserName`/`TargetDomainName`), TS-LSM 21/25 (`Address`, `User`), and credible service installs (System 7045, Security 4697, Sysmon 13).

**Logic.** For each credible install, the rule looks for inbound movement edges to the same
`Computer` from 0 to `window` before it, ignoring machine accounts, ANONYMOUS LOGON null
sessions (SID `S-1-5-7`, so localized names count too) and 4648 edges. If it finds any, it
reports the install with the closest preceding logon's user and source. The evidence is the
install record. The logon is described by the finding's user and source, so allowlist it with
`users` and `sources`.

**Severity:** high. It becomes **critical** when the service name or image matches
`psexe|paexec|remcom|csexec|winexe`. A command-line image alone does not escalate CW-001.

**Tunables:** `window = "10m"`.

```toml
[[allow]]
reason = "Deployment server installs its agent service after logging on"
rules = ["CW-001"]
users = ["CORP\\svc_deploy"]
sources = ["10.0.5.0/24"]
expires = 2027-06-30
[[allow.fields]]                    # System 7045: the name and the binary
ServiceName = "^ExampleAgent$"
ImagePath = '^"?C:\\Program Files\\ExampleAgent\\agent\.exe"?$'
[[allow.fields]]                    # Security 4697, on hosts without the System log
ServiceName = "^ExampleAgent$"
ServiceFileName = '^"?C:\\Program Files\\ExampleAgent\\agent\.exe"?$'
```

The name alone is not enough: a service called `ExampleAgent` whose image is a PowerShell
command line would pass it.

**False positives.** Software deployment, patching and any admin who logs on remotely and
installs a service within ten minutes. The rule only checks timing on the same host, so an
unrelated logon that happens to come just before a legitimate install also gets the blame.

**Blind spots.** The rule needs **two kinds of evidence from the target**: a logon (4624 or
TS-LSM 21/25) plus an install. A System-only export never fires, and a Security-only export
fires only if it also has 4697 install events. A renamed
tool with a plain binary path that only Sysmon 13 records is missed. That is a deliberate
trade against Defender-style ImagePath rewrites. Installs more than `window` after the logon
are missed, and the logon and the install must carry the same `Computer` string.

**Validation.** There is no corpus entry. On the full corpus the rule produces zero findings at
the default window. `Lateral Movement/LM_Remote_Service02_7045.evtx` installs `remotesvc`
39 minutes after the last inbound logon recorded in a separate sample. With `window = "45m"`,
`crabwalk hunt` over `Lateral Movement` reports `followed 2364s later by install of service
'remotesvc' (calc.exe)`. That run joins two separately captured samples, so it only
illustrates the window and does not count as validation. Unit tests: the nine
`test_psexec_pattern_*`, `test_*install*` and `test_sysmon_13_*` tests in
`tests/test_rules.py` cover the critical escalation, merging of cross-log copies, Sysmon 13
credibility, an install outside the window, and an ANONYMOUS LOGON (English and German names)
that must not take the blame; `test_an_account_merely_named_anonymous_is_not_exempt` checks
that the SID decides. `test_window_tunable_changes_what_correlates` is in
`tests/test_config.py`.

## CW-002: RDP chain across hosts

**ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol

**Data sources:** Security 4624 with `LogonType` 10 (`IpAddress`, `WorkstationName`), and TS-LSM 21/25 (`Address`, `User`). Both become movement edges with logon type 10.

**Logic.** Two RDP edges form a chain A -> B -> C when the second starts after the first, by at
most `window`, its source resolves to the first hop's destination B, and its destination is a
different host C. A source resolves to its `WorkstationName` (short form). Failing that, it
resolves to its IP, mapped to a name only if some RDP edge paired that IP with one. Each
(A, B, C, second user) is reported once; A is resolved the same way, so a first hop that B
logged both as 4624 and as TS-LSM 21 counts once. The two hops need not share a user.

**Severity:** high, always.

**Tunables:** `window = "6h"`.

```toml
[[allow]]
reason = "Administrators RDP to servers through the jump host"
rules = ["CW-002"]
sources = ["JUMP01"]
```

The evidence is the two hop records (4624 or TS-LSM 21/25). They carry who and where
(`IpAddress`, `Address`, `WorkstationName`, the account), which is what `users`, `hosts` and
`sources` express; a field table made only of those is refused. The finding's source is the
second hop's source, or B itself when that hop has no name.

**False positives.** Jump hosts, bastions and admin workstations used as stepping stones are
the main source. A user who RDPs from B to another host within six hours after a different
user's RDP session into B also links up, because the two hops' users are not compared.

**Blind spots.** The rule needs RDP evidence from **both** B and C, so collection must cover
more than one host. TS-LSM 21/25 record only an address. If C names B only by an IP that was
never seen next to a host name, the hop does not link. RCM 1149 and 4778 reconnects are not
used. Chains longer than three hosts are reported as overlapping pairs.

**Validation.** There is no corpus entry, because the corpus has no logon-type-10 or TS-LSM
21/25 edges (checked by listing every edge from the full-corpus context). Unit test:
`test_rdp_chain_across_three_hosts` and
`test_rdp_chain_is_reported_once_when_both_logs_record_the_first_hop` (`tests/test_rules.py`).

## CW-003: Pass-the-hash indicators

**ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) Use Alternate Authentication Material: Pass the Hash

**Data sources:** Security 4624 (`LogonType`, `LogonProcessName`, `AuthenticationPackageName`, `TargetUserName`, `TargetOutboundUserName`, `IpAddress`, `WorkstationName`, `TargetLogonId`) and Security 4672, which supplies the privileged flag.

**Logic.** Machine accounts and ANONYMOUS LOGON are skipped. Anonymous is decided by
`TargetUserSid` `S-1-5-7`, and by the name only when the record has no SID, so an account
someone named `anonymous1` is not exempt.
The rule has two branches:

1. **Signature:** `LogonType` 9 with `LogonProcessName` `seclogo`, reported with the
   outbound user name. This event is logged on the host where the hash was *used*, not on the
   target.
2. **Privileged NTLM network logon:** `LogonType` 3, package `NTLM`, and a 4672 seen for the
   same LogonId on the same host. This branch is controlled by `privileged_ntlm`. Tools
   open a new session per operation, so one run leaves a burst of such logons: those from
   one source address (or, without one, one workstation name), as one account, on one host,
   each within `burst_gap` of the previous, are **one** finding citing all of them ("14
   privileged NTLM network logons from 10.23.123.11 over 8 s"). The workstation name is
   whatever the client sends: impacket's logons in both corpora leave it blank, and a
   Metasploit `ms17_010_psexec` recording sends a made-up 16-character one. So the finding
   names a source host only when every logon in the burst gives the same name.

**Severity:** high for the signature branch, medium for the NTLM branch.

**Tunables:** `privileged_ntlm = true`, `burst_gap = "10m"`. Setting `privileged_ntlm` to
`false` keeps the signature branch and drops the NTLM branch.

```toml
[[allow]]
reason = "Backup server authenticates with NTLM as a privileged service account"
rules = ["CW-003"]
users = ["CORP\\svc_backup"]
sources = ["10.0.5.10"]
```

**False positives.** Microsoft defines logon type 9 as any *NewCredentials* logon: a caller
clones its token with new outbound credentials
([4624 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)).
So branch 1 does not prove that a hash was used: `runas /netonly` produces the same event.
On the corpus it also fires on
`Privilege Escalation/security_4624_4673_token_manip.evtx`,
`Privilege Escalation/Invoke_TokenDuplication_UAC_Bypass4624.evtx` and
`Credential Access/tutto_malseclogon.evtx`. Branch 2 fires on any admin tool that falls back
to NTLM. On the corpus it gives 5 medium findings in 3 files, none of them PtH samples.

**Blind spots.** Pass-the-hash seen only from the target side looks like an ordinary NTLM
network logon. If 4672 is missing or `privileged_ntlm = false`, that case is not reported.
The signature branch also fires for overpass-the-hash on the source host, because it is the
same LT9/seclogo event. Sigma's "Successful Overpass the Hash Attempt" rule matches that
event, additionally requiring package `Negotiate`, which CW-003 does not check
([SigmaHQ rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml)).
On the target, overpass-the-hash appears as a Kerberos network logon, which the NTLM branch
does not cover. Pass-the-ticket is not covered.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`
(T1550.002). Unit tests: `test_pth_seclogo_logon_type_9`, `test_pth_privileged_ntlm_needs_4672`,
`test_pth_burst_of_privileged_ntlm_logons_is_one_finding`,
`test_pth_bursts_split_on_gap_source_and_account`.
Config test: `test_privileged_ntlm_switch_keeps_the_seclogo_signature`. On the full corpus:
9 findings (4 high, 5 medium). The burst grouping came from the second corpus, where one
run of 14 logons on one host in 8 seconds gave 14 findings that differed only in their time.

## CW-004: Scheduled task created from remote session

**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task

**Data sources:** Security 4698/4702 (`SubjectLogonId`, `TaskName`, `TaskContent` on 4698 / `TaskContentNew` on 4702) and the 4624 logon session behind that LogonId.

**Logic.** The rule matches the task event's `SubjectLogonId` to a logon session on the same
host. It reports the task if that session is remote, meaning its 4624 had a real source
address. There is no time window: the link is by LogonId. The summary includes the task's
`<Command>`, from `TaskContent` (4698) or `TaskContentNew` (4702).

**Severity:** high, always. **Tunables:** none.

```toml
[[allow]]
reason = "Deployment account registers the agent update task remotely"
rules = ["CW-004"]
users = ["CORP\\svc_deploy"]
[[allow.fields]]                    # 4698, task created
TaskName = '^\\ExampleAgent\\Update$'
TaskContent = '(?s)^(?!(?:.*?<Actions\b){2}).*?<Actions Context="[^"]*">\s*<Exec>\s*<Command>"?C:\\Program Files\\ExampleAgent\\agent\.exe"?</Command>(?:\s*<Arguments>--update</Arguments>)?\s*</Exec>\s*</Actions>'
[[allow.fields]]                    # 4702, task updated: the XML is in TaskContentNew
TaskName = '^\\ExampleAgent\\Update$'
TaskContentNew = '(?s)^(?!(?:.*?<Actions\b){2}).*?<Actions Context="[^"]*">\s*<Exec>\s*<Command>"?C:\\Program Files\\ExampleAgent\\agent\.exe"?</Command>(?:\s*<Arguments>--update</Arguments>)?\s*</Exec>\s*</Actions>'
```

A task's name says nothing about what it runs, so each table also pins the task's whole
`<Actions>` element: exactly one `Exec` of the agent, with at most its known argument. A second
action of any kind (another `Exec`, a `ComHandler`), other arguments, or a second `<Actions`
anywhere in the XML fails the regex.

**False positives.** Remote management and deployment tools that register tasks over the
network.

**Blind spots.** The 4624 for that LogonId must be present in the same export. A type-3 logon
with no usable `IpAddress` is not remote. In
`Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx` the task's LogonId (`0x17e2d2`)
belongs to such a logon, so CW-004 stays silent there. That task is caught by CW-012 through
`atsvc` instead. LogonIds are only unique per boot, so a log that spans reboots can in
principle link the wrong session.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/remote task update 4624 4702 same logonid.evtx`
(T1053.005). Unit tests: `test_remote_scheduled_task`, `test_local_scheduled_task_is_quiet`.
On the full corpus: 1 finding.

## CW-005: Executable on administrative share

**ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares; [T1570](https://attack.mitre.org/techniques/T1570/) Lateral Tool Transfer

**Data sources:** Security 5145 (`ShareName`, `RelativeTargetName`, `IpAddress`, `SubjectUserName`/`SubjectDomainName`).

**Logic.** The rule takes 5145 events where `ShareName` ends in `ADMIN$` or `C$` and
`RelativeTargetName` ends in one of the configured extensions. It reports each
(host, share, file, user) once per run.

**Severity:** high, always.

**Tunables:** `extensions = [".exe", ".dll", ".bat", ".ps1", ".cmd"]`. Each value is
normalized to a lower-case dotted extension, and globs are rejected. CW-012's own drop list
(the same five plus `.scr`) is fixed and is **not** changed by this setting.

```toml
[[allow]]
reason = "Software distribution copies the agent installer to ADMIN$"
rules = ["CW-005"]
sources = ["10.0.5.0/24"]
[allow.fields]
ShareName = '\\ADMIN\$$'            # C:\Windows; the same path over C$ is C:\Temp
RelativeTargetName = '^Temp\\ExampleAgentSetup\.exe$'
```

**False positives.** A 5145 is an access check on a share object
([5145 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145)),
and the rule does not inspect `AccessMask` or `AccessList`. Reading an executable over `C$`,
for example during inventory or when an admin copies a file *off* the host, also fires.

**Blind spots.** The rule needs the *Audit Detailed File Share* subcategory on the target.
Shares are matched by name suffix, so other drive shares (`D$`) are missed, while any share
whose name ends in `C$` (for example `PUBLIC$`) is included by accident. CW-012's drop list
uses the same test. Payloads with other extensions
(`.vbs`, `.hta`, `.msi`, `.sys`) are missed unless added to `extensions`.

**Merging.** When CW-012 credits the same `ADMIN$` or `C$` record to a remote-execution cluster
of the same account and client, this finding is listed under the CW-012 one instead of
standing alone (see "One event, one finding").

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_renamed_psexecsvc_5145.evtx` (T1021.002)
and `Lateral Movement/LM_REMCOM_5145_TargetHost.evtx` (T1570); in the first the CW-005 is
merged into the CW-012, which the harness counts as fired. Unit test:
`test_admin_share_executable_deduplicates`; `tests/test_narrative.py` covers the merge
(`test_the_drop_inside_a_psexec_run_is_told_once`, `test_a_drop_no_execution_follows_stays_a_finding`).
Config test: `test_extension_tunable_is_normalized`. On the full corpus: 8 matches; the two
drops CW-012 credits (`blabla.exe` on IEWIN7, `RemComSvc.exe` on PC01) are merged into those
findings, leaving 6 findings, 5 of them in `Lateral Movement/LM_5145_Remote_FileCopy.evtx`.

## CW-006: Process spawned via WMI

**ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation

**Data sources:** Sysmon 1 (`ParentImage`, `Image`, `CommandLine`, `User`) and Security 4688 (`ParentProcessName`, `NewProcessName`, `CommandLine`; the user is `TargetUserName`/`TargetDomainName`, the account the process runs as, when the event has them, else `SubjectUserName`/`SubjectDomainName`).

**Logic.** Every process whose parent's file name is `wmiprvse.exe`. The summary shows
`CommandLine`, or the child's file name when there is no command line. The source is the
remote network logon the process runs in, when its 4624 was logged (see "Where a spawned
process came from").

**Severity:** high when the child is one of `cmd.exe`, `powershell.exe`, `pwsh.exe`,
`wscript.exe`, `cscript.exe`, `rundll32.exe`, `regsvr32.exe` or `mshta.exe`. Medium otherwise.
**Tunables:** none.

```toml
[[allow]]
reason = "Monitoring agent runs its collector through WMI"
rules = ["CW-006"]
hosts = ["SRV*"]
[[allow.fields]]                    # Sysmon 1
Image = '^C:\\Program Files\\ExampleMonitor\\collector\.exe$'
CommandLine = '^"C:\\Program Files\\ExampleMonitor\\collector\.exe" --once$'
[[allow.fields]]                    # Security 4688
NewProcessName = '^C:\\Program Files\\ExampleMonitor\\collector\.exe$'
CommandLine = '^"C:\\Program Files\\ExampleMonitor\\collector\.exe" --once$'
```

A command-line prefix is not enough: `"C:\Program Files\ExampleMonitor\..\..\Windows\System32\cmd.exe"`
starts with it. The tables pin the resolved image (`Image` in Sysmon 1, `NewProcessName` in
4688) and the whole command line.

**False positives.** The rule cannot tell local WMI use from remote. Management agents,
WMI-based inventory and local WMI event consumers all fire. On the corpus,
`Persistence/sysmon_20_21_1_CommandLineEventConsumer.evtx` is persistence rather than
movement.

**Blind spots.** Without the 4624 of the caller's session (a Sysmon-only export, or one
host's Security log cut before the logon) no source is recorded, so the finding is not drawn
as a graph edge. On the corpus only
`Privilege Escalation/NTLM2SelfRelay-med0x2e-security_4624_4688.evtx` has one: its process
runs in a Kerberos network logon from 192.168.1.219. WMI-Activity 5857-5861 are
cataloged but unused. WMI execution that does not create a process as a child of WmiPrvSE is
not visible.

**Validation.** `GROUND_TRUTH`: `Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx`
(T1047). That sample is a credential-dumping capture, not a WMI lateral-movement one. It
proves the rule only because WMI is the launcher there: WmiPrvSE starts
`rundll32 C:\windows\system32\comsvcs.dll, MiniDump ...`. The impacket wmiexec sample
`Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx` is **not** a `GROUND_TRUTH` entry.
Hunted on its own, it gives 3 high CW-006 findings such as
`cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__... 2>&1`. Unit tests:
`test_wmi_spawned_shell_is_high`, `test_wmi_child_takes_its_source_from_the_network_logon`.
On the full corpus: 15 findings in 8 files.

## CW-007: Remote execution via WinRM

**ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/) Remote Services: Windows Remote Management

**Data sources:** Sysmon 1 and Security 4688 (same fields as CW-006), and WinRM/Operational 91 (System `UserID`).

**Logic.** There are two branches. (1) Every child process of `wsmprovhost.exe` (PowerShell
remoting) or `winrshost.exe` (`winrs`, Windows Remote Shell over WinRM), handled the same way
as CW-006, source included. (2) Every WinRM event 91 (shell created on this host), reported
with the event's user SID.

**Severity:** high for a shell child (same list as CW-006), medium otherwise, and medium for
event 91. **Tunables:** none.

```toml
[[allow]]
reason = "Server admins use PowerShell remoting on management hosts"
rules = ["CW-007"]
hosts = ["MGMT*"]
```

For event 91 the finding's user is a SID, so a `users` pattern must be the SID.

**False positives.** Every legitimate PowerShell remoting session.

**Blind spots.** Event 91 carries no client address, so no source is recorded. WinRM 6 and
168 are not used.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`
and `Lateral Movement/LM_winrm_exec_sysmon_1_winrshost.evtx` (T1021.006). Unit tests:
`test_winrm_shell_event`, `test_winrs_shell_is_winrm`. On the full corpus: 3 findings. The
third is `Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx`, which
is not a ground-truth entry. The `winrshost.exe` branch closes a gap the
[benchmark](BENCHMARK.md) found: both rule engines flagged the winrs sample, crabwalk did not.

## CW-008: Suspicious PowerShell script block

**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell

**Data sources:** PowerShell/Operational 4104 (`ScriptBlockText`, System `UserID`).

**Logic.** Case-insensitive regexes over each script block. One finding lists every label
that matched:

| Label | Pattern | Severity |
|---|---|---|
| credential theft tooling | `invoke-mimikatz\|sekurlsa\|lsadump` | critical |
| AMSI bypass | `amsiutils\|amsiinitfailed` | high |
| download cradle | `downloadstring\|downloadfile\|net\.webclient\|invoke-webrequest\|start-bitstransfer` | high |
| base64 decode + invoke | `frombase64string` | medium |
| invoke-expression | `\biex\b\|invoke-expression` | medium |

**Severity:** the worst matched label. **Tunables:** none.

```toml
[[allow]]
reason = "Inventory task downloads its script from the internal repo (runs as SYSTEM)"
rules = ["CW-008"]
hosts = ["WKS*"]
users = ["S-1-5-18"]
[allow.fields]
ScriptBlockText = '^iex \(New-Object Net\.WebClient\)\.DownloadString\("https://repo\.corp\.local/inventory/inv\.ps1"\)$'
```

Script text is attacker-controlled. An unanchored match on `repo.corp.local/inventory` would
also suppress a cradle that mentions that string in a comment, so the regex pins the whole
script block, and the entry is scoped to the account (the 4104 user is a SID) and hosts.

**False positives.** The "base64 decode + invoke" label fires on `FromBase64String` alone; no
invoke is required. `iex` and the download keywords also appear in ordinary admin and
installer scripts.

**Blind spots.** Plain keyword matching is defeated by string obfuscation such as
concatenation, tick marks or `[char]` building. Each 4104 part of a long script is evaluated
on its own. Script block logging must be on. 4103 module logging is not read.

**Validation.** `GROUND_TRUTH`: `Other/emotet/exec_emotet_ps_4104.evtx` (T1059.001). Unit
tests: `test_suspicious_powershell_download_cradle`, `test_benign_powershell_is_quiet`. On the
full corpus: 2 findings.

## CW-009: Event log cleared

**ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs

**Data sources:** Security 1102 and System 104 (`SubjectUserName`/`SubjectDomainName`; for 104 also `Channel` or `BackupPath`).

**Logic.** Every such event is a clear. A tool that clears every log (`wevtutil cl` in a loop)
leaves one record per channel, so clears on one host by one account, each within
`burst_gap` of the previous, are **one** finding that lists the channels ("cleared 89 event
logs (Application, ForwardedEvents, HardwareEvents and 86 more)"). The same clear kept in two
exports (same time and channel) counts once. **Severity:** high, always.

**Tunables:** `burst_gap = "1m"`.

```toml
[[allow]]
reason = "Lab images are rebuilt and their logs cleared by the build account"
rules = ["CW-009"]
hosts = ["LAB-*"]
users = ["CORP\\svc_build"]
```

**False positives.** Administrators clearing logs during maintenance or image builds. This
shows up on the corpus: besides its two dedicated samples, CW-009 fires on 24 more files. Each
of those hits is the file's EventRecordID 1, which fits the sample author clearing the log
before each capture. The events are real; they just are not part of the attack.

**Blind spots.** Clearing that leaves no 1102/104 is not detected. That includes stopping the
EventLog service, deleting `.evtx` files offline, or tampering with individual records. Gaps
in the record sequence are not analyzed.

**Validation.** `GROUND_TRUTH`: `Defense Evasion/DE_1102_security_log_cleared.evtx` and
`Defense Evasion/DE_104_system_log_cleared.evtx` (both T1070.001). Unit tests:
`test_log_cleared_and_dedup`, `test_clearing_every_log_at_once_is_one_finding`. On the full
corpus: 24 findings. Two of them group clears of one host from two files: those two
ground-truth samples (PC01, System then Security 41 s later) and two Zerologon captures of
one host (`01566s-win16-ir`, 13 s apart). The grouping came from the second corpus, where one file's 91 clears (a System and a
Security clear minutes apart, then 89 channels within 3 s) gave 91 findings; it now gives 3.

## CW-010: Kerberoasting (RC4 service ticket)

**ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Steal or Forge Kerberos Tickets: Kerberoasting

**Data sources:** Security 4769 on domain controllers (`TicketEncryptionType`, `Status`, `ServiceName`, `TargetUserName`, `IpAddress`).

**Logic.** A successful service-ticket request (`Status` `0x0` or missing) with
`TicketEncryptionType` equal to `0x17` (RC4-HMAC). Tickets for `krbtgt` or for a machine
account (`$`) are skipped, and so are requests made by a machine account, including in UPN
form. Each event is its own finding; there is no volume threshold.

**Severity:** high, always. **Tunables:** none.

```toml
[[allow]]
reason = "Legacy application service account only supports RC4 (ticket INC-1234)"
rules = ["CW-010"]
expires = 2026-12-31
[allow.fields]
ServiceName = "^svc_legacyapp$"
```

**False positives.** Service accounts and clients that still negotiate RC4. Microsoft's 4769
guidance calls `0x11`/`0x12` (AES) the expected values from Windows Server 2008 / Vista on,
and lists `0x17` as the default for older systems
([4769 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)).
A single legacy ticket fires just like a roast of fifty SPNs.

**Blind spots.** Roasting that requests AES tickets is not flagged. 4769 is generated only on
domain controllers under *Audit Kerberos Service Ticket Operations*, so DC logs must be
collected. There is no per-requester count or burst logic.

**Validation.** **No corpus sample.** The corpus has two 4769 events, both `0x12`, in
`Privilege Escalation/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx`,
and the rule correctly ignores them. Unit tests only: `test_kerberoasting_rc4_ticket`,
`test_kerberoasting_ignores_aes_and_machine_accounts`,
`test_kerberoasting_ignores_machine_requesters_in_upn_form`.

## CW-011: DCSync (directory replication)

**ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) OS Credential Dumping: DCSync

**Data sources:** Security 4662 on domain controllers (`Properties`, `SubjectUserName`, `SubjectDomainName`).

**Logic.** `Properties` contains one of the replication extended-right GUIDs:
DS-Replication-Get-Changes `1131f6aa-...`, -Get-Changes-All `1131f6ad-...`, or
-Get-Changes-In-Filtered-Set `89e95b76-...`. The subject must not be a machine account, empty,
or ANONYMOUS LOGON. Domain controllers replicate as their `$` accounts. The rule reports one
finding per (host, principal) per run.

**Severity:** critical, always. **Tunables:** none.

```toml
[[allow]]
reason = "Entra Connect password hash sync (AD DS Connector account)"
rules = ["CW-011"]
users = ["CORP\\MSOL_*"]
```

**False positives.** Accounts that are legitimately granted replication rights. Microsoft
Entra Connect's AD DS Connector account needs Replicate Directory Changes and Replicate
Directory Changes All for password hash sync. Express setup creates it with an `MSOL_` prefix
([Entra Connect accounts](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions)).

**Blind spots.** A DCSync run under a domain controller's machine account (for example with a
stolen DC account secret) is excluded by design. 4662 appears only under *Audit Directory
Service Access* with a matching SACL on the object
([4662 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662)).
Repeat replications by the same principal are collapsed into the first finding.

**Validation.** `GROUND_TRUTH`: `Credential Access/CA_DCSync_4662.evtx` (T1003.006). Unit
tests: `test_dcsync_by_non_dc_principal_is_critical`,
`test_dcsync_ignores_domain_controller_machine_account`,
`test_dcsync_ignores_non_replication_object_access`. On the full corpus: 1 finding.

## CW-012: Remote execution over named pipes

**ATT&CK:** The techniques depend on the evidence. [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares is attached to remote findings only. [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution is attached when a tool pipe, `svcctl`/`ntsvcs` or a credited install is involved, so an `atsvc`-only or random-pipe finding does not carry it. Corroboration adds [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service (install), [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task (task) and [T1570](https://attack.mitre.org/techniques/T1570/) Lateral Tool Transfer (drop).

**Data sources:**
- Sysmon 17/18 (`PipeName`, `Image`). A Sysmon 18 whose `Image` is `System` arrived over SMB. Sysmon logs 17/18 for the pipes its `PipeEvent` filter includes
  ([Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)).
- Security 5145 on `IPC$` (`RelativeTargetName`, `IpAddress`, subject account).
- For corroboration: credible service installs, 4698/4702, and 5145 executable drops on `ADMIN$`/`C$`.

The rule works on Sysmon-only exports, Security-only exports, or both.

**Logic.**
1. **Classify** each pipe hit:
   - *tool*: default pipes of PsExec (`PSEXESVC`), RemCom/impacket (`RemCom*`), PAExec,
     CSExec and Cobalt Strike (`MSSE-<n>-server`, `msagent_`/`postex_`/`status_` + hex), and
     PsExec stdio pipes `<service>-<HOST>-<pid>-stdin|stdout|stderr`;
   - *control*: a remote `svcctl`/`ntsvcs` or `atsvc` hit;
   - *random*: a remote hit on a name of 16 or more hex characters.

   All other pipes are ignored.
2. **Cluster** hits per (host, client address), splitting on gaps longer than `cluster_gap`.
   A Sysmon hit takes the client of the same-pipe 5145 within `skew` (or the only such client
   within `cluster_gap`). An address-less cluster joins the single address cluster it
   overlaps, so concurrent clients stay apart.
3. **Credit corroboration.** A drop goes to the nearest cluster of the same client, from
   `drop_window` before it to `skew` after. An install or task (tasks only to `atsvc`
   clusters) goes to a cluster with activity within `follow_window` before it. Clusters with
   a drop or tool pipe are preferred, then the most recent one, so a poller cannot take credit
   for an attacker's burst.
4. **Enumeration guard.** A cluster with no tool pipe and no corroboration is dropped when its
   own client touched at least `enum_distinct_pipes` distinct remote pipes within
   `enum_window` around it.
5. **Local vs remote.** Local evidence is any of: a tool pipe connected by a local process
   (Sysmon 18, Image not `System`), a stdio pipe naming this host, or a loopback-only 5145.
   With local evidence and no signature pipe driven from another machine, the finding is
   titled "Local execution through a remote-exec tool's pipes" and carries no T1021.002 and
   no source. PsExec run against its own host (`PsExec -s -i cmd`) reaches its service pipe
   over SMB loopback, which Sysmon logs as a `System` connect, while the client opens the
   stdio pipes itself. So each local run whose stdio pipes are opened locally and name this
   host excuses one connect: the address-less `System` connect to its service pipe closest
   before its first local stdio connect, within `skew`. Every other `System` connect to that
   pipe, and any a 5145 ties to a remote client, still makes the cluster remote.
6. **Source host.** The source host is taken from the stdio pipe name. Renamed services that
   contain dashes are resolved against a main pipe seen on the host. A remote finding takes
   it only from stdio pipes that no local process opened and that do not name this host, so
   a local run next to a remote one never makes the target its own source.
7. **Telling it.** The summary names the first credited drop, install and task and counts
   the others ("(+N more)"); the story phrase names up to three drops and up to two installs
   or tasks (tasks as created for 4698 or updated for 4702, with their command), then counts
   the rest. A finding merged into this one stays listed in full under "also matched". A drop
   is told as "copied" / "written to" only when its 5145 asks for write access (`AccessMask`
   with WriteData `0x2` or AppendData `0x4`), otherwise as "accessed"; detection itself
   credits any access to an executable name.

**Severity.** The strongest pipe kind sets the base: tool -> high, control -> medium,
random -> medium. Control plus corroboration -> high. The finding becomes **critical** for a
tool pipe plus corroboration, a dropped file whose name matches
`psexe|paexec|remcom|csexec|winexe`, or a credited install that looks like remote execution.
Local execution is always medium.

**Tunables** (`[rules.CW-012]`): `cluster_gap = "2m"`, `follow_window = "2m"`,
`drop_window = "5m"`, `skew = "5s"`, `enum_window = "30s"`, `enum_distinct_pipes = 5`.

```toml
[[allow]]
reason = "Monitoring server polls service status over svcctl"
rules = ["CW-012"]
sources = ["10.0.5.20"]
[[allow.fields]]                    # the 5145 opens on IPC$
RelativeTargetName = "^svcctl$"
[[allow.fields]]                    # the Sysmon 18 connects, on hosts that log them too
PipeName = '^\\svcctl$'
```

This entry hides the polling and nothing more. When an install follows the same client's
svcctl open, the escalated finding is kept, because no table describes the credited 7045.
Verified on the corpus, with the entry pointed at `10.0.2.17`:
`LM_Remote_Service01_5145_svcctl.evtx` alone gives `suppressed : 1 by allowlist`. Together
with `LM_Remote_Service02_7045.evtx`, the HIGH "svcctl, then install of `remotesvc`" finding
is kept, and `hunt` warns that "no fields table describes their System 7045 evidence". To
allow a known install as well, add a table that pins its name and binary, as in the CW-001
snippet (`ServiceName` and `ImagePath`). The
`PipeName` table matters on hosts that log Sysmon 17/18 as well as 5145: without it, the
Sysmon 18 records in each polling cluster are left undescribed and every cluster is kept.

**False positives.** Legitimate remote service management (`sc \\host`, the Services console
pointed at a remote machine, deployment tools) appears as control pipes. Administrators'
legitimate PsExec use is reported as high or critical. Software that names its pipes with
16+ hex characters triggers the random branch.

**Blind spots.**
- The tool-pipe list is fixed and not tunable. A tool configured with other pipe names is
  only caught through svcctl/ntsvcs/atsvc or a 16+ hex name.
- Only Sysmon 18 with Image `System` or a 5145 with a non-loopback address counts as remote.
- Sysmon-13-only installs of renamed tools with a plain binary do not corroborate (see
  "Shared building blocks").
- An attacker who also sweeps five or more pipes in the same window, with no tool pipe and no
  install, task or drop, is suppressed as enumeration.

**Validation.**
- `GROUND_TRUTH` (6 entries): `Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx`
  (T1569.002), `Lateral Movement/LM_renamed_psexecsvc_5145.evtx` (T1569.002),
  `Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx` (T1543.003),
  `Lateral Movement/lm_sysmon_18_remshell_over_namedpipe.evtx` (T1021.002),
  `Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx` (T1053.005),
  `Lateral Movement/LM_Remote_Service01_5145_svcctl.evtx` (T1021.002).
- `NEGATIVE_TRUTH` (must stay silent): `Discovery/Discovery_Remote_System_NamedPipes_Sysmon_18.evtx`,
  `Discovery/discovery_bloodhound.evtx`, `Discovery/discovery_psloggedon.evtx`,
  `Credential Access/remote_sam_registry_access_via_backup_operator_priv.evtx`.
- `test_psexec_pipe_names_reveal_the_source_host`: on `LM_renamed_psexecsvc_5145.evtx`, the
  finding is critical with source `10.0.2.16` / `NLLT108334`.
- `test_local_psexec_is_not_called_lateral_movement`: on
  `DE_renamed_psexec_service_sysmon_17_18.evtx` and
  `Privilege Escalation/sysmon_privesc_psexec_dwell.evtx`, the finding is titled local, has
  no T1021.002 and no source.
- Unit tests: the 30 test functions in `tests/test_pipes.py` (concurrent clients, poller
  ticks, enumeration, local vs remote, Sysmon/5145 merging). Four of them,
  `test_psexec_against_its_own_host_over_smb_loopback_is_local`,
  `test_a_remote_client_on_the_service_pipe_is_not_excused_as_loopback`,
  `test_a_local_run_excuses_only_its_own_loopback_connect` and
  `test_a_remote_run_beside_a_local_one_takes_its_own_source_host`, come from the second
  corpus: its `PSexec as system execution` sample was reported as critical lateral
  movement. In the first corpus's local sample the service was renamed (`svchost`), so its
  loopback connect never matched a tool pipe and the gap stayed hidden.
- On the full corpus: 8 findings (3 critical, 2 high, 3 medium). Both HIGH findings draw
  evidence from two corpus files of host `WIN-77LTAPHIQ1R`:
  - "svcctl, then install of `remotesvc`" joins the Security 5145 in
    `LM_Remote_Service01_5145_svcctl.evtx` with the System 7045 in
    `LM_Remote_Service02_7045.evtx`, 47 ms later. Hunted on its own, the svcctl sample gives
    only a MEDIUM svcctl finding, and that is what its `GROUND_TRUTH` entry checks.
  - "atsvc, then task `\CYAlyNSS`" lists the same 4698 twice, from
    `LM_ScheduledTask_ATSVC_target_host.evtx` and `Execution/temp_scheduled_task_4698_4699.evtx`.
    The ATSVC sample is HIGH on its own; the second file only adds a duplicate copy.

## CW-013: Execution through DCOM

**ATT&CK:** [T1021.003](https://attack.mitre.org/techniques/T1021/003/) Remote Services: Distributed Component Object Model

**Data sources:** Sysmon 1 (`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessId`, `ParentProcessId`, `LogonId`) and Security 4688 (`NewProcessName`, `ParentProcessName`, `CommandLine`, `NewProcessId`, `ProcessId`, logon IDs); for the source, the 4624 of the process's logon session, else inbound Sysmon 3 connections of the COM server process.

**Logic.** Remote DCOM activation starts the COM server under `svchost.exe -k DcomLaunch`
with `-Embedding` on its command line. The servers the rule knows are `mmc.exe`
(MMC20.Application), `mshta.exe` (htafile), `excel.exe`, `winword.exe` and `outlook.exe`.
It reports:

1. **A child of an activated COM server.** On Sysmon 1 the parent's `ParentCommandLine`
   contains `-Embedding`. A 4688 has no parent command line, so there only `mmc.exe`
   spawning a shell counts: Office spawning one is as often a local macro.
2. **The activation itself.** For `mshta.exe -Embedding` started by `svchost.exe` always:
   that runs an HTA (the LethalHTA technique), with or without a child. For the other
   servers only when the server runs in a remote caller's network logon, which is what
   remote activation does; without that logon, an activation says nothing on its own.

The source is the network logon the process runs in (see "Where a spawned process came
from"). Without one, the rule reads the COM server process's **inbound** Sysmon 3
connections: same host and process ID (Sysmon `ProcessId`; on a 4688 the server's ID is
`NewProcessId` for the activation and the creator's `ProcessId` for a child), from the
server's start (or `peer_window` before the event when its start is not logged) to
`peer_window` after the event. When they name exactly one remote peer, that is the source,
with the host name Sysmon resolved for it, and those connections are cited. A connection the
server opened itself (an HTA fetching its payload) is never taken as its caller.

**Severity:** high for a shell child (the CW-006 list) and for an activation, medium for any
other child.

**Tunables:** `peer_window = "1m"`.

```toml
[[allow]]
reason = "Reporting server drives Excel on the finance hosts over DCOM"
rules = ["CW-013"]
sources = ["10.0.5.30"]
hosts = ["FIN*"]
```

Legitimate remote use of these COM objects to start processes is rare, so this entry
narrows by who and where only. When the finding cites a Sysmon 3 connection, a `fields`
entry cannot match it (see "Allowlisting").

**False positives.** Office automation driven from another host (reporting, document
generation). A child of a server activated locally with `-Embedding`, for example a local
script driving `MMC20.Application` that starts a shell, is reported too, with no source.
A local maldoc that reaches mshta through `ShellBrowserWindow` does not match: explorer.exe
starts that mshta, without `-Embedding`. COM use inside an RDP session names no source.

**Blind spots.** `ShellWindows` and `ShellBrowserWindow` run their command inside the
existing `explorer.exe`, so a child of explorer.exe is indistinguishable from the user's
own; the corpus sample of them has only Sysmon 3 records and stays silent. Other COM
objects used for lateral movement (Visio, third-party servers) are not in the list. A failed
activation (System 10016) is not reported. The source side of a DCOM call (a PowerShell
script block creating `MMC20.Application` on another host) is not detected, only the target.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_impacket_docmexec_mmc_sysmon_01.evtx` and
`Lateral Movement/LM_DCOM_MSHTA_LethalHTA_Sysmon_3_1.evtx` (T1021.003). `NEGATIVE_TRUTH`:
`Other/maldoc_mshta_via_shellbrowserwind_rundll32.evtx`. Unit tests in `tests/test_dcom.py`
cover children and activations on Sysmon and 4688, process IDs on both logs, the direction
and window of the peer connection, its host name, local and RDP-session COM use, and LogonIds
reused across boots. On the full corpus: 4 findings in those two files (3 for the three
impacket commands, source `10.0.2.19`; 1 for LethalHTA, source `10.0.2.17`). The rule closes
the DCOM gap the [benchmark](BENCHMARK.md) found. Its activation branch came from the second
corpus, whose MMC20 sample shows the activation in a logon from `10.23.123.11` and no child.

## CW-014: Startup folder written from another host

**ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder; over SMB also [T1021.002](https://attack.mitre.org/techniques/T1021/002/) and [T1570](https://attack.mitre.org/techniques/T1570/) Lateral Tool Transfer; over RDP [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Desktop Protocol

**Data sources:** Sysmon 11 (`Image`, `TargetFilename`), kept at parse time only for files in a Startup folder; Security 5145 (`ShareName`, `RelativeTargetName`, `AccessMask`, `IpAddress`, subject account); Sysmon 3 for the source.

**Logic.** A file created in a Startup folder runs at the next logon. A Startup folder is
`...\Start Menu\Programs\Startup\` under a profile or ProgramData, also written with its 8.3
short names (`STARTM~1`). The rule reports one written by another machine:

1. **Over SMB.** A Sysmon 11 whose writer is the SMB server (`Image` `System`, or
   `<unknown process>`), or a 5145 on any share but `IPC$` that asks for write access (as in
   CW-012) to a path in a Startup folder from a non-loopback address. A 5145 names its
   client in `IpAddress`. For a Sysmon 11 alone the source is the one remote peer of the
   **inbound** connections on port 445 within `peer_window` of the write; with several,
   none is named and all are listed. If those connections are all loopback
   (`\\localhost\C$`), a process on this host wrote the file and there is no finding.
2. **Over RDP.** A Sysmon 11 written by `mstsc.exe`: the RDP client writing a file that the
   server it is connected to pushed through the client's shared drive (`\\tsclient`). The
   movement runs from that server back to this client. The source is the server of the
   latest **outbound** `mstsc.exe` connection on port 3389 within `rdp_window` before the
   write.

The records of one copy (several 5145 access checks, the Sysmon 11) are one finding: same
host, same channel (SMB or RDP), same file in the same profile's Startup folder, each within
`peer_window` of the previous. The finding names whose folder it is (`bob's`, `the
all-users`, or `a` when the path is in neither layout).

**Severity:** high, always.

**Tunables:** `peer_window = "1m"`, `rdp_window = "12h"`.

```toml
[[allow]]
reason = "Login-script server copies the helpdesk shortcut into Startup folders over C$"
rules = ["CW-014"]
sources = ["10.0.5.40"]
[[allow.fields]]                    # the 5145 write on C$
RelativeTargetName = '^Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Helpdesk\.lnk$'
[[allow.fields]]                    # the Sysmon 11 of the same copy, on hosts that log it
Image = '^System$'
TargetFilename = '^C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Helpdesk\.lnk$'
```

One copy's 5145 and Sysmon 11 are one finding, so the entry needs a table for each. When a
host logs only Sysmon 11, the finding also cites the inbound SMB connection that names the
source, which no table can describe, so this entry keeps it; allowlist that case with
`sources` and `hosts`.

**False positives.** Deployment tools and login scripts that copy shortcuts into Startup
folders over the network. A file server that stores roaming profiles or redirected folders:
every profile sync over SMB writes there. A user copying a file into their own Startup
folder while connected over RDP with drive redirection.

**Blind spots.** Sysmon logs 11 only for paths its configuration's `FileCreate` rules
include. Other autostart locations (Run keys written over remote registry, scheduled tasks)
are not this rule. Without a write-access 5145 or a Sysmon 11, a file copied into a Startup
folder leaves nothing for it to read.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/lateral_movement_startup_3_11.evtx`
(T1547.001, source `10.0.2.17`, named `MSEDGEWIN10CLON` by Sysmon) and
`Lateral Movement/LM_tsclient_startup_folder.evtx` (T1021.001). `NEGATIVE_TRUTH`:
`AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` and
`Defense Evasion/sysmon_2_11_evasion_timestomp_MACE.evtx`, where local `powershell.exe` and
`cmd.exe` write into Startup folders. Unit tests in `tests/test_remote_files.py` cover the
parse-time filter, 8.3 names, both channels, one finding per copy, folder owners, loopback and
outbound SMB, and the peer's name. On the full corpus: 2 findings, the two ground-truth files.

## CW-015: Program run from an RDP client's drive

**ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol; [T1570](https://attack.mitre.org/techniques/T1570/) Lateral Tool Transfer

**Data sources:** Sysmon 1 (`Image`, `CommandLine`, `LogonId`) and Security 4688 (`NewProcessName`, `CommandLine`); for the source, the 4624 of the process's RDP session, else Sysmon 3.

**Logic.** A process whose image or command line points into the drive the connecting RDP
client shares with this host: `\\tsclient\...`, which a 4688 logs as
`\Device\Mup\tsclient\...`. The program sits on the client and runs on this host, which is
how SharpRDP and similar tools move a binary over RDP. When only the command line points
there (a local `cmd` copying from it), the finding says so. The source is the RDP session
the process runs in (logon type 10 or 7) or, without one, the peer of the latest **inbound**
connection on port 3389 within `rdp_window` before it, with the name Sysmon resolved for it.

**Severity:** medium, always: an administrator running a tool from their own drive looks the
same.

**Tunables:** `rdp_window = "12h"`.

```toml
[[allow]]
reason = "Helpdesk runs the support tool from their own drive over RDP"
rules = ["CW-015"]
users = ["CORP\\helpdesk1"]
[[allow.fields]]                    # Sysmon 1
Image = '^\\\\tsclient\\c\\Tools\\support\.exe$'
CommandLine = '^"?\\\\tsclient\\c\\Tools\\support\.exe"? ?$'
[[allow.fields]]                    # Security 4688
NewProcessName = '^\\Device\\Mup\\tsclient\\c\\Tools\\support\.exe$'
CommandLine = '^"?\\\\tsclient\\c\\Tools\\support\.exe"? ?$'
```

Each table pins the binary as well as the command line: a command line alone can be set to
any value by whoever starts the process. The optional trailing space is how Sysmon logs a
program Explorer starts with no arguments.

On a Sysmon-only host where the source comes from a Sysmon 3 connection, the finding cites
that connection and this entry keeps it; allowlist that case with `users`, `hosts` and
`sources`.

**False positives.** Administrators and helpdesk staff running tools from their own drive.

**Blind spots.** A binary copied from `\\tsclient` to a local path first and run from there
is caught only through the copy's command line. On a server with several RDP sessions at
once, the latest inbound connection may belong to another session; the logon session, when
logged, settles it.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_sysmon_1_12_13_3_tsclient_SharpRdp.evtx`
(T1021.001, source `192.168.56.1`, named `LAPTOP-JU4M3I0E` by Sysmon). Unit tests in
`tests/test_remote_files.py` cover Sysmon and 4688 paths, the RDP-connection direction and a
local program handed a `\\tsclient` path. On the full corpus: 1 finding, that file. The other
SharpRDP sample (`LM_sysmon_3_12_13_1_SharpRDP.evtx`) types its command into the Run dialog
and stays silent.

---

## Summary

| Rule | Technique(s) | Sources | Corpus-validated |
|---|---|---|---|
| CW-001 | T1021.002, T1543.003 | Security 4624 / TS-LSM 21,25 + System 7045 / Security 4697 / Sysmon 13 | No (unit tests only) |
| CW-002 | T1021.001 | Security 4624 LT10, TS-LSM 21,25 (multi-host) | No (unit test only) |
| CW-003 | T1550.002 | Security 4624, 4672 | Yes |
| CW-004 | T1053.005 | Security 4698, 4702 + 4624 | Yes |
| CW-005 | T1021.002, T1570 | Security 5145 (ADMIN$/C$) | Yes |
| CW-006 | T1047 | Sysmon 1, Security 4688 | Yes (via a credential-dumping sample) |
| CW-007 | T1021.006 | Sysmon 1, Security 4688, WinRM 91 | Yes (wsmprovhost and winrshost) |
| CW-008 | T1059.001 | PowerShell 4104 | Yes |
| CW-009 | T1070.001 | Security 1102, System 104 | Yes |
| CW-010 | T1558.003 | Security 4769 (DC) | No (unit tests only) |
| CW-011 | T1003.006 | Security 4662 (DC) | Yes |
| CW-012 | T1021.002 (remote only); T1569.002 (tool pipe, svcctl/ntsvcs, install); +T1543.003, T1053.005, T1570 by corroboration | Sysmon 17/18, Security 5145 (IPC$), + installs, 4698/4702, 5145 drops | Yes (6 positive, 4 negative) |
| CW-013 | T1021.003 | Sysmon 1, Security 4688 (+ 4624 / Sysmon 3 for the source) | Yes (2 positive, 1 negative) |
| CW-014 | T1547.001; + T1021.002, T1570 (SMB) or T1021.001 (RDP) | Sysmon 11 (Startup folders), Security 5145 (+ Sysmon 3) | Yes (2 positive, 2 negative) |
| CW-015 | T1021.001, T1570 | Sysmon 1, Security 4688 (+ 4624 / Sysmon 3) | Yes (1 positive) |
