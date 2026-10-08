# crabwalk detection reference

This reference covers crabwalk's twelve detection rules: what each one reads, the logic it
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
- WinRM 6/168, WMI-Activity 5857-5861, PowerShell 4103, Windows PowerShell 400/403, Sysmon 3.

They appear in `parse` output, never in findings. Security 4634/4647 only set session end
times, and 4648 only adds an outbound edge to the session graph.

## How the rules are validated

- **Unit tests** (`tests/test_rules.py`, `tests/test_pipes.py`, `tests/test_config.py`) run
  each rule on synthetic events. `pytest tests`: 381 passed.
- **Ground-truth corpus** (`tests/test_corpus.py`) runs over
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0, not
  vendored, under `samples/EVTX-ATTACK-SAMPLES`). `GROUND_TRUTH` has 16 (file, technique,
  rule) entries whose filenames name the technique or the behaviour the rule keys on (CW-006
  is the exception; see its section). `NEGATIVE_TRUTH` has 4 files of *other* attacker
  activity on which a rule must stay silent. Each entry is hunted **one file at a time**,
  and a finding merged under another rule's still counts as that rule firing, both ways.
  `pytest tests/test_corpus.py`: 26 passed.
- **Whole-corpus run.** `crabwalk hunt samples/EVTX-ATTACK-SAMPLES` covers 278 files and
  37,364 records (0 unparsable) and yields 72 findings (4 critical, 51 high, 17 medium),
  after two CW-005 matches are merged into the CW-012 findings that cite them.
  CW-001, CW-002 and CW-010 produce **zero** of them.

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

**Severity levels** are `critical`, `high` and `medium`. No rule emits `low`. Findings that
are identical in (rule, time, host, user, summary) are collapsed.

**One event, one finding.** A finding is merged into another rule's finding that already
tells it: one that cites every record it cites, claims at least its techniques at no lower
severity, adds something (more records, techniques or severity), and names the same host,
the same account and source (or none), within 10 minutes. The merged finding is listed under
the other ("also matched", in full in the JSON) and still counts as fired for the corpus
tests. In practice CW-012 absorbs the CW-005 drop it credits, and could absorb a CW-001 or
CW-004 about the same install or task by the same actor; findings that disagree about who
did it, or from where, stay separate (`merge_overlaps()` in `rules/__init__.py`).

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
`OriginalFileName`, `ScriptBlockText`, `Properties`, `ObjectName`, `Channel` or `BackupPath`.
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
   same LogonId on the same host. This branch is controlled by `privileged_ntlm`.

**Severity:** high for the signature branch, medium for the NTLM branch.

**Tunables:** `privileged_ntlm = true`. Setting it to `false` keeps the signature branch and
drops the NTLM branch.

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
to NTLM. On the corpus it gives 7 medium findings in 3 files, none of them PtH samples.

**Blind spots.** Pass-the-hash seen only from the target side looks like an ordinary NTLM
network logon. If 4672 is missing or `privileged_ntlm = false`, that case is not reported.
The signature branch also fires for overpass-the-hash on the source host, because it is the
same LT9/seclogo event. Sigma's "Successful Overpass the Hash Attempt" rule matches that
event, additionally requiring package `Negotiate`, which CW-003 does not check
([SigmaHQ rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml)).
On the target, overpass-the-hash appears as a Kerberos network logon, which the NTLM branch
does not cover. Pass-the-ticket is not covered.

**Validation.** `GROUND_TRUTH`: `Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx`
(T1550.002). Unit tests: `test_pth_seclogo_logon_type_9`, `test_pth_privileged_ntlm_needs_4672`.
Config test: `test_privileged_ntlm_switch_keeps_the_seclogo_signature`. On the full corpus:
11 findings (4 high, 7 medium).

## CW-004: Scheduled task created from remote session

**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task

**Data sources:** Security 4698/4702 (`SubjectLogonId`, `TaskName`, `TaskContent`) and the 4624 logon session behind that LogonId.

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

**Merging.** When CW-012 credits the same `ADMIN$` record to a remote-execution cluster
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
`CommandLine`, or the child's file name when there is no command line.

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

**Blind spots.** No source host is recorded, so the finding is not drawn as a graph edge.
WMI-Activity 5857-5861 are cataloged but unused. WMI execution that does not create a process
as a child of WmiPrvSE is not visible.

**Validation.** `GROUND_TRUTH`: `Credential Access/sysmon_10_1_memdump_comsvcs_minidump.evtx`
(T1047). That sample is a credential-dumping capture, not a WMI lateral-movement one. It
proves the rule only because WMI is the launcher there: WmiPrvSE starts
`rundll32 C:\windows\system32\comsvcs.dll, MiniDump ...`. The impacket wmiexec sample
`Lateral Movement/LM_wmiexec_impacket_sysmon_whoami.evtx` is **not** a `GROUND_TRUTH` entry.
Hunted on its own, it gives 3 high CW-006 findings such as
`cmd.exe /Q /c whoami /all 1> \\127.0.0.1\ADMIN$\__... 2>&1`. Unit test:
`test_wmi_spawned_shell_is_high`. On the full corpus: 15 findings in 8 files.

## CW-007: Remote execution via WinRM

**ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/) Remote Services: Windows Remote Management

**Data sources:** Sysmon 1 and Security 4688 (same fields as CW-006), and WinRM/Operational 91 (System `UserID`).

**Logic.** There are two branches. (1) Every child process of `wsmprovhost.exe`, handled the
same way as CW-006. (2) Every WinRM event 91 (shell created on this host), reported with the
event's user SID.

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
(T1021.006). Unit test: `test_winrm_shell_event`. On the full corpus: 2 findings. The second
is `Lateral Movement/LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx`, which is not
a ground-truth entry.

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

**Logic.** Every such event is a finding. **Severity:** high, always. **Tunables:** none.

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
`Defense Evasion/DE_104_system_log_cleared.evtx` (both T1070.001). Unit test:
`test_log_cleared_and_dedup`. On the full corpus: 26 findings.

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
   no source.
6. **Source host.** The source host is taken from the stdio pipe name. Renamed services that
   contain dashes are resolved against a main pipe seen on the host.
7. **Telling it.** The summary and the story phrase name every credited drop, install and
   task (tasks as created for 4698, updated for 4702, with their command), so findings merged
   into this one lose nothing. A drop is told as "copied" only when its 5145 asks for write
   access (`AccessMask` with WriteData `0x2` or AppendData `0x4`), otherwise as "accessed";
   detection itself credits any access to an executable name.

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
- Unit tests: the 26 test functions in `tests/test_pipes.py` (concurrent clients, poller
  ticks, enumeration, local vs remote, Sysmon/5145 merging).
- On the full corpus: 8 findings (3 critical, 2 high, 3 medium). Both HIGH findings draw
  evidence from two corpus files of host `WIN-77LTAPHIQ1R`:
  - "svcctl, then install of `remotesvc`" joins the Security 5145 in
    `LM_Remote_Service01_5145_svcctl.evtx` with the System 7045 in
    `LM_Remote_Service02_7045.evtx`, 47 ms later. Hunted on its own, the svcctl sample gives
    only a MEDIUM svcctl finding, and that is what its `GROUND_TRUTH` entry checks.
  - "atsvc, then task `\CYAlyNSS`" lists the same 4698 twice, from
    `LM_ScheduledTask_ATSVC_target_host.evtx` and `Execution/temp_scheduled_task_4698_4699.evtx`.
    The ATSVC sample is HIGH on its own; the second file only adds a duplicate copy.

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
| CW-007 | T1021.006 | Sysmon 1, Security 4688, WinRM 91 | Yes |
| CW-008 | T1059.001 | PowerShell 4104 | Yes |
| CW-009 | T1070.001 | Security 1102, System 104 | Yes |
| CW-010 | T1558.003 | Security 4769 (DC) | No (unit tests only) |
| CW-011 | T1003.006 | Security 4662 (DC) | Yes |
| CW-012 | T1021.002 (remote only); T1569.002 (tool pipe, svcctl/ntsvcs, install); +T1543.003, T1053.005, T1570 by corroboration | Sysmon 17/18, Security 5145 (IPC$), + installs, 4698/4702, 5145 drops | Yes (6 positive, 4 negative) |
