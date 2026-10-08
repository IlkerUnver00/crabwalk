# Sigma rules for crabwalk's building blocks

crabwalk's CW-012 rule ([`src/crabwalk/rules/pipes.py`](../src/crabwalk/rules/pipes.py))
reconstructs remote execution over named pipes by correlating many events. The rules in
this directory are the single-event pieces of evidence it starts from, written as Sigma
so they can run in a SIEM. crabwalk itself does not load them.

| File | Rule | Log source | Level |
|---|---|---|---|
| `pipe_created_psexec_renamed_service_stdio.yml` | PsExec-style stdio pipe, renamed service | Sysmon 17/18 | high |
| `win_security_psexec_renamed_service_stdio_ipc.yml` (document 1) | Same pipe shape, opened remotely on IPC$ | Security 5145 | high |
| `win_security_psexec_renamed_service_stdio_ipc.yml` (document 2) | Executable written to ADMIN$/C$ (building block) | Security 5145 | low |
| `win_security_psexec_renamed_service_stdio_ipc.yml` (document 3) | Correlation: drop and renamed-PsExec pipes from the same client within 5 min (any order) | Security 5145 | critical |
| `registry_set_service_imagepath_command_line.yml` | Service ImagePath set to a cmd.exe command line | Sysmon 13 | high |
| `pipe_created_inbound_smb_random_hex_pipe.yml` | Inbound SMB connection to a random hex pipe | Sysmon 18 | medium |

All rules are `status: experimental`. They were validated with pySigma and tested against
the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus,
nothing more (see [Validation](#validation)). Nobody has run them against a production
baseline, so false-positive rates are unknown.

## The primitives

**PsExec stdio pipes.** In the corpus, PsExec's stdio pipes are named
`<service>-<client host>-<client pid>-stdin|stdout|stderr`:
`\svchost-MSEDGEWIN10-8116-stdin` in Sysmon, and `blabla-NLLT108334-37048-stdin` in
5145 `RelativeTargetName`. `psexec -r` changes the service name
([Sysinternals docs](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec):
"Specifies the name of the remote service to create or interact with"). As both
renamed-service samples show, the stdio pipes carry the new name. Rules keyed on `\PSEXESVC` miss that case. The host segment names the
machine the PsExec client ran on, and CW-012 uses it to recover the source host. Both
rules match the anchored shape `^<no dash>-<anything>-<digits>-std(in|out|err)$` and
exclude the default `PSEXESVC-` prefix, which the SigmaHQ default-pipe rules already
cover.

**Service ImagePath as a command line.** impacket `smbexec.py` builds its service binary
path from `'%COMSPEC% /Q /c '`
([source](https://github.com/fortra/impacket/blob/1875828d0f2e987cd89c1bcb45f843708981a199/examples/smbexec.py)). In the
corpus, the Sysmon 13 in `LM_sysmon_psexec_smb_meterpreter.evtx` shows the ImagePath of
service `hello` set to `%%COMSPEC%% /b /c start /b /min powershell.exe -nop -w hidden ...`. crabwalk
treats a Sysmon 13 ImagePath write as an install only when the image looks like remote
execution: a command line, PowerShell (`powershell`, `-enc`, `-nop`), a staging path such
as `\ADMIN$\`, `\Windows\Temp\` or `\Users\Public\`, or a known tool name (`psexe`, `paexec`,
`remcom`, `csexec`, `winexe`) in the service name or image (`credible_installs()` in
[`rules/lateral.py`](../src/crabwalk/rules/lateral.py)). That way it still sees the
install when the System log is missing, and stays quiet on routine ImagePath rewrites.
The Sigma rule keeps only the command-interpreter part of that test: `%COMSPEC%`,
`cmd[.exe] /c|/k|/q` with a single space (crabwalk's regex allows any whitespace), and the
`\\127.0.0.1\` UNC prefix (other loopback forms such as `\\localhost\` are not matched by
either). It requires the key to be `<ControlSet>\Services\<name>\ImagePath` exactly.

**Random hex pipes over SMB.** Sysmon logs a pipe connection made on behalf of a remote
SMB client with `Image` `System`, as in the corpus's remote-shell sample
`lm_sysmon_18_remshell_over_namedpipe.evtx`. A connection like that to a pipe named only
with 16 or more hex digits is the shape of named-pipe remote shells. But `System` only
says the open arrived through the SMB server, and a client on the same host can arrive
that way too (loopback SMB). In the corpus, 34 Sysmon 18 events carry `Image` `System`, and
8 of them come from local activity: 7 from local privilege-escalation samples (`spoolss`,
`frAQBc8Wsa1`, RoguePotato `epmapper`, two EfsPotato pipes, `PSEXESVC`, `samir`) and one from
`DE_renamed_psexec_service_sysmon_17_18.evtx`, where the local PsExec connects to its own
main pipe `\svchost` as `System`. CW-012's first pass marks every `System` 18 as remote
(`event_id == 18` and the basename of `Image` is `system`) and then corrects that from the
rest of the cluster (see below). The Sigma rule cannot, so it does not prove a remote source.

## Overlap with SigmaHQ

Checked against [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) `master` at commit
`8a48134` (2026-10-06), searching `rules/`, `rules-threat-hunting/` and
`rules-emerging-threats/`. The links below are permalinks to that commit. The corpus
results in the Difference column come from running each SigmaHQ rule through the same
evaluator used for these rules (see [Validation](#validation)).

| Our rule | Overlapping SigmaHQ rules | Difference |
|---|---|---|
| Stdio pipe, Sysmon | [PsExec Default Named Pipe](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules-threat-hunting/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe.yml) (f3f3a972), [PsExec Tool Execution From Suspicious Locations - PipeName](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe_susp_location.yml) (41504465); on Sysmon 1: [Renamed PsExec Service Execution](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_psexec_service.yml) (51ae86a2) | Both pipe rules match exactly `\PSEXESVC`. No `pipe_created` rule in the three folders matches the stdio suffix, so a renamed service is invisible to SigmaHQ's pipe rules. It is still caught by 51ae86a2 (`OriginalFileName: psexesvc.exe`, excluding `C:\Windows\PSEXESVC.exe`) when Sysmon EID 1 is collected, as long as the service binary is a renamed copy of the real PSEXESVC rather than a clone. In the corpus, both pipe rules fire only on the default-name sample (`sysmon_privesc_psexec_dwell.evtx`) and not on `DE_renamed_psexec_service_sysmon_17_18.evtx`, where ours fires. That file holds only Sysmon 17/18 events, so no SigmaHQ rule fires on it. |
| Stdio pipe, 5145 | [Suspicious PsExec Execution](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/builtin/security/win_security_susp_psexec.yml) (c462f537), the [Zeek variant](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/network/zeek/zeek_smb_converted_win_susp_psexec.yml), [First Time Seen Remote Named Pipe](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/builtin/security/win_security_lm_namedpipe.yml) (52d8b0c6) | This is a **derived** rule (`related: derived`), not a new idea. c462f537 matches any name ending in `-stdin`/`-stdout`/`-stderr` and excludes names starting with `PSEXESVC`. Ours requires the full `<svc>-<host>-<pid>-<stream>` shape and drops loopback clients. On the corpus both fire on the same 3 events. The difference is precision on names this corpus does not contain. 52d8b0c6 is an allowlist rule: it fired on 6 corpus events, the 3 stdio pipes, the main `blabla` pipe and two pipes from other samples (`samir`, `pipey`). |
| ImagePath command line, Sysmon 13 | [PowerShell as a Service in Registry](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/registry/registry_set/registry_set_powershell_as_service.yml) (4a5f5a5e), [Potential CobaltStrike Service Installations - Registry](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/registry/registry_set/registry_set_cobaltstrike_service_installs.yml) (61a7697c), [Service Binary in Suspicious Folder](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/registry/registry_set/registry_set_creation_service_susp_folder.yml) (a07f0359); on System 7045: [smbexec.py Service Installation](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/builtin/system/service_control_manager/win_system_hack_smbexec.yml), [Meterpreter or Cobalt Strike Getsystem Service Installation](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/builtin/system/service_control_manager/win_system_meterpreter_or_cobaltstrike_getsystem_service_installation.yml), [Suspicious Service Installation](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml) | On the registry side, SigmaHQ covers PowerShell images, the Cobalt Strike shape (`%COMSPEC%` + `start` + `powershell`, or `ADMIN$` + `.exe`) and suspicious folders. A cmd-only image such as smbexec's `%COMSPEC% /Q /c echo ...` or getsystem's `cmd.exe /c echo ... > \\.\pipe\...` is covered on 7045 but not on Sysmon 13. Ours fills that gap and deliberately leaves PowerShell and folders to the existing rules. In the corpus, ours fires on 2 events (`hello`, `msdhch`). 4a5f5a5e and 61a7697c each fire only on `hello`. |
| Random hex pipe, Sysmon 18 | [Malicious Named Pipe Created](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/pipe_created/pipe_created_susp_malicious_namedpipes.yml) (fe3ac066), [CobaltStrike Named Pipe Pattern Regex](https://github.com/SigmaHQ/sigma/blob/8a4813404ea3074890e0cda9272d4d1a8b2941d6/rules/windows/pipe_created/pipe_created_hktl_cobaltstrike_re.yml) | fe3ac066 lists `\46a676ab7f179e511e30dd2dc41bd388` (commented "Project Sauron") as an exact IOC, so on this corpus it fires on the same single event as ours. Ours matches the shape (any all-hex name, connection arrived via SMB, remote or loopback) instead of the name. The corpus cannot show whether that generalizes, because it holds only this one hex pipe. The Cobalt Strike regexes need fixed prefixes. |
| Correlation | none | SigmaHQ at `8a48134` contains no `correlation:` rules in the three folders searched. |

## What a single event cannot say

Each rule above looks at one event, while CW-012 decides from the whole cluster around
it. It groups signature pipe hits per (host, client address), splitting them after a
gap (120 s by default). Address-less Sysmon hits borrow the client of the 5145 record of
the same pipe open within 5 s. A service install (7045, 4697, or a Sysmon 13 ImagePath
write that looks like remote execution) or a task is credited to the cluster that most
plausibly caused it: first one with corroborating context (a binary the same client
dropped, or a tool pipe), then the most recent activity strictly before it within 120 s.
A poller therefore cannot take credit from a cluster that has a dropped binary or a tool
pipe; between two clusters without such context (for example impacket smbexec, which drives
`svcctl` and drops no binary, next to a `svcctl` poller), the more recent one still wins.
CW-012 also parses the source host out of the stdio pipe name, using a main pipe seen on
the same host to handle service names that contain dashes, and draws it as an attack-graph
edge. Finally, it decides local versus remote from the other side of the pipe. On
`DE_renamed_psexec_service_sysmon_17_18.evtx`, the Sysmon rule here fires on 6 events
(3 creates by `C:\Windows\svchost.exe`, 3 connects by `C:\Windows\system32\PsExec.exe`).
crabwalk reports one finding there: `[MEDIUM] CW-012 Local execution through a remote-exec
tool's pipes ... client ran on this host by psexec.exe`. That is a renamed PsExec, but no
lateral movement. None of that context exists inside a single event: Sysmon pipe events
carry no client address, 7045 carries none either, and the client process is a different
record from the pipe creation.

[Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-correlation-rules-specification.md)
(spec 2.1.0) close part of this gap. `temporal` and `temporal_ordered` require several
rules to match within a timespan for the same `group-by` values, and `value_count` could
express "many distinct pipes from one client" (CW-012's enumeration test). Document 3 of
the IPC$ file uses `temporal` to tie an ADMIN$ executable drop to renamed-PsExec pipes
from the same `Computer` and `IpAddress`. That is the per-client part of CW-012, and it
works only because both events are 5145s carrying `IpAddress`. The rest stays out of
reach. Group-by needs a field that every correlated event shares, so a Sysmon pipe event
or a 7045 can only group by host, and two concurrent clients on one host merge. A window
expresses co-occurrence, not "the most recent cluster before the install". The spec has
no way to extract the host segment from a pipe name, and no negation or absence ("this
pipe, but no remote 5145 for it"), so local versus remote and enumeration suppression
cannot be written down. The SIEM translation also loses precision; see the caveats below.

## Validation

Environment: a throwaway venv outside the repository (Python 3.12.10), with packages
from PyPI:

```text
pySigma 1.5.1
pysigma-backend-splunk 2.1.0
pysigma-pipeline-sysmon 2.0.0
pysigma-pipeline-windows 2.0.1
pySigma-validators-sigmahq 0.21.0   (second venv, same versions otherwise; lint only)
```

**Parse and lint.** All four files were loaded with
`SigmaCollection.load_ruleset(..., collect_errors=True)`, and the detection rules were
checked with every validator pySigma ships (`sigma.validators.core.validators`, 31 of
them, among them ATT&CK tag, identifier existence and uniqueness, invalid modifier
combination and escaped-wildcard checks):

```text
loaded 5 detection rules + 1 correlation rule(s) from 4 files
parse errors: 0
validator issues (31 validators, detection rules): 0
```

Those are pySigma's core validators only. SigmaHQ's own convention validators
(`pySigma-validators-sigmahq`, 49 `sigmahq_*` validators) were run separately, on the
detection rules. After the reference links were changed to commit permalinks, they
report 2 issues, both on the hex-pipe rule and both intentional:

```text
sigmahq: 2 issues
   SigmahqRedundantFieldIssue ['Inbound SMB Connection To A Random Hex Named Pipe'] EventID
   SigmahqCategoryEventIdIssue ['Inbound SMB Connection To A Random Hex Named Pipe']
```

Both say the `EventID` field is not needed under `category: pipe_created` ("already
covered by the logsource"). That category covers Sysmon 17 and 18, and the rule keeps
`EventID: 18` on purpose because it is about connections, not creations.

**Conversion.** `SplunkBackend(sysmon_pipeline() + splunk_windows_pipeline())` converted
each rule, then the whole collection in one `backend.convert(collection)` call (6
queries, no errors). The output, verbatim:

```text
## Inbound SMB Connection To A Random Hex Named Pipe
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (17, 18) EventCode=18 Image="System"
| regex PipeName="^\\\\[0-9A-Fa-f]{16,}$"

## PsExec-Style Stdio Named Pipe With Renamed Service
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (17, 18) NOT PipeName="\\PSEXESVC-*"
| regex PipeName="(?i)^\\\\[^-\\\\]+-.+-[0-9]+-std(?:in|out|err)$"

## Service ImagePath Set To A Command Interpreter Line
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 Details IN ("*%COMSPEC%*", "*cmd /c*", "*cmd /k*", "*cmd /q*", "*cmd.exe /c*", "*cmd.exe /k*", "*cmd.exe /q*", "*cmd.exe\" /c*", "*cmd.exe\" /k*", "*cmd.exe\" /q*", "*\\\\127.0.0.1\\*")
| regex TargetObject="(?i)\\\\(?:CurrentControlSet|ControlSet[0-9]{3})\\\\Services\\\\[^\\\\]+\\\\ImagePath$"

## Remote PsExec-Style Stdio Pipe With Renamed Service On IPC$
source="WinEventLog:Security" EventCode=5145 ShareName="*\\IPC$" NOT (RelativeTargetName="PSEXESVC-*" OR IpAddress IN ("127.*", "::ffff:127.*") OR IpAddress="::1")
| regex RelativeTargetName="(?i)^[^-\\\\]+-.+-[0-9]+-std(?:in|out|err)$"

## Executable Written To ADMIN$ Or C$ Over SMB
source="WinEventLog:Security" EventCode=5145 ShareName IN ("*\\ADMIN$", "*\\C$") RelativeTargetName IN ("*.exe", "*.dll", "*.bat", "*.cmd", "*.ps1", "*.scr") AccessList IN ("*%%4417*", "*WriteData*")

## Admin Share Executable Drop And Renamed PsExec Stdio Pipe From The Same Client
| multisearch
[ search source="WinEventLog:Security" EventCode=5145 ShareName IN ("*\\ADMIN$", "*\\C$") RelativeTargetName IN ("*.exe", "*.dll", "*.bat", "*.cmd", "*.ps1", "*.scr") AccessList IN ("*%%4417*", "*WriteData*") | eval event_type="cw_admin_share_executable_write" ]
[ search source="WinEventLog:Security" EventCode=5145 ShareName="*\\IPC$" NOT (RelativeTargetName="PSEXESVC-*" OR IpAddress IN ("127.*", "::ffff:127.*") OR IpAddress="::1")
| regex RelativeTargetName="(?i)^[^-\\\\]+-.+-[0-9]+-std(?:in|out|err)$" | eval event_type="cw_psexec_renamed_service_stdio_ipc" ]

| bin _time span=5m
| stats dc(event_type) as event_type_count by _time Computer IpAddress

| search event_type_count >= 2
```

The queries use the raw EVTX field names (`PipeName`, `RelativeTargetName`, `Computer`,
...). Map them to whatever your Splunk add-on extracts. These queries were generated,
not run in a Splunk instance.

**Corpus run.** `crabwalk parse samples/EVTX-ATTACK-SAMPLES --all --event-id 17
--event-id 18 --event-id 5145 --event-id 13 --event-id 7045 --event-id 4697 --out
ev.jsonl` exported 1250 events from all 278 files. A throwaway evaluator (not in this
repo) walked each rule's pySigma-parsed condition tree over those events. It handles
wildcard strings case-insensitively, regexes with their flags, and the `temporal`
correlation as a sliding window per group-by key:

```text
## Inbound SMB Connection To A Random Hex Named Pipe: 1 of 61 candidate events
  1 x EID 18  \46a676ab7f179e511e30dd2dc41bd388  [lm_sysmon_18_remshell_over_namedpipe.evtx]
## PsExec-Style Stdio Named Pipe With Renamed Service: 6 of 61 candidate events
  3 x EID 17, 3 x EID 18  \svchost-MSEDGEWIN10-8116-std{in,out,err}  [DE_renamed_psexec_service_sysmon_17_18.evtx]
## Service ImagePath Set To A Command Interpreter Line: 2 of 223 candidate events
  1 x EID 13  HKLM\System\CurrentControlSet\services\hello\ImagePath  [LM_sysmon_psexec_smb_meterpreter.evtx]
  1 x EID 13  HKLM\System\CurrentControlSet\services\msdhch\ImagePath  [sysmon_13_1_meterpreter_getsystem_NamedPipeImpersonation.evtx]
## Remote PsExec-Style Stdio Pipe With Renamed Service On IPC$: 3 of 958 candidate events
  3 x EID 5145  blabla-NLLT108334-37048-std{in,out,err}  [LM_renamed_psexecsvc_5145.evtx]
## Executable Written To ADMIN$ Or C$ Over SMB: 12 of 958 candidate events
  2 x Windows\Temp\setup.bat, 2 x malwr.exe [LM_5145_Remote_FileCopy.evtx]; 6 x System32\RemComSvc.exe [LM_REMCOM_5145_TargetHost.evtx]; 2 x blabla.exe [LM_renamed_psexecsvc_5145.evtx]
## Admin Share Executable Drop And Renamed PsExec Stdio Pipe From The Same Client (TEMPORAL, 300s, by ['Computer', 'IpAddress'])
  group ('IEWIN7', '10.0.2.16'): all 2 rules within 300s; first hit per rule: drop 13:00:10.350688, stdio pipe 13:00:10.711207
  group ('PC01.example.corp', '10.0.2.15'): incomplete (drop only)
  group ('PC01.example.corp', '10.0.2.16'): incomplete (drop only)
```

(Condensed for this page: hits differing only in the stream suffix or file share one
line, and the correlation lines say "drop" and "stdio pipe" instead of the rule names.
The counts are unchanged.) The `msdhch` hit is Meterpreter
`getsystem`, a local privilege escalation. The rule is right that the service is
malicious, but it is not lateral movement. crabwalk's full rule set (`crabwalk hunt`)
reports 0 findings on that file: it holds no remote logon and no pipe activity to tie
the install to.

**Caveats found while validating:**

- `pysigma-backend-splunk` 2.1.0 raises `NotImplementedError: Correlation type
  'temporal_ordered' is not supported by backend`. The correlation therefore uses
  `temporal`, and the drop-before-pipe order is not enforced.
- The Splunk correlation query buckets time with `bin _time span=5m`. A drop and a pipe
  open that straddle a bucket boundary are not joined, even when they are seconds apart.
- With the correlation in its own file, sorted before the file of the rule it
  references, `backend.convert(collection)` failed with "Conversion result not available"
  for the referenced rule. Keeping the correlation in the same file, after both base rules,
  converts cleanly. `generate: true` keeps the 5145 stdio rule's own alert, and it also
  emits the low-level drop rule as a standalone query.
- `generate` sits inside `correlation:` because that is where pySigma 1.5.1 reads it
  (`correlation_rule.get("generate")` in `sigma/correlations.py`). Spec 2.1.0 and its JSON
  schema place it at the top level, next to `level`, so tools that follow the spec may
  ignore it there.
- A `|re` value inside an OR with `|contains` values makes the Splunk backend emit `rex`
  and `eval` helper fields (`DetailsMatch`, `DetailsCondition`) in front of the `search`.
  The ImagePath rule keeps its OR to plain `contains` values, so its query stays one
  `search` plus one `regex` filter.

**In the EVTX rule engines (tested 2026-10-08).** The rules are valid Sigma, but two common
offline engines need a flag or a small rewrite to run them. Each file was run on the corpus
sample it was written for, during the [benchmark](../docs/BENCHMARK.md):

| Engine | Loads | Fires as written | Why |
|---|---|---|---|
| Hayabusa 4.1.0 (`dfir-timeline -r sigma/`) | all 6 rule documents | none by default; all with `-A` | Hayabusa's channel filter skips rules that name no `Channel` ("Detection rules enabled after channel filter: 1"), and raw Sigma rules leave the channel to the `logsource`. With `-A` (`--enable-all-rules`) every file fires as written, `\|re\|i` and the correlation included: the IPC$ and ADMIN$ rules on records 84050 to 84052 and 84038 to 84039, the correlation once, the three Sysmon rules on their samples (6, 1 and 1 events). Adding `Channel: Security` to the IPC$ rule is also enough. |
| Chainsaw 2.16.5 (`hunt -s sigma/ --mapping sigma-event-logs-all.yml`) | 1 of 5 rules | the hex-pipe rule, on its sample | `chainsaw lint` rejects the others with "unsupported modifiers - i": the Sigma 2.0 `\|re\|i` sub-modifier. Rewritten as `\|re` with an inline `(?i)`, all files validate and all five rules fire on their samples: the IPC$ and ADMIN$ rules on 3 and 2 records, the Sysmon stdio-pipe and ImagePath rules on 6 and 1 events. Chainsaw does not run the correlation. This repo keeps `\|re\|i`, the spec's portable form. |

To use them there, run Hayabusa with `-A`, and for Chainsaw replace `|re|i: '...'` with
`|re: '(?i)...'`. The benchmark also found that neither engine fires SigmaHQ's own
*Suspicious PsExec Execution* rule on `LM_renamed_psexecsvc_5145.evtx` as shipped, because of
how they match its escaped `ShareName` value; see [BENCHMARK.md](../docs/BENCHMARK.md#cases).
