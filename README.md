# crabwalk

[![CI](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml/badge.svg)](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Live demo](https://img.shields.io/badge/live%20demo-report%20%C2%B7%20graph%20%C2%B7%20ATT%26CK-2a78d6)](https://ilkerunver00.github.io/crabwalk/)

**Windows EVTX lateral movement hunter** — parses Windows event logs, correlates
logon/service/scheduled-task/named-pipe/PowerShell activity across hosts, draws the
result as an **attack-path graph**, tells it as a dated **attack story**, and maps
every finding to MITRE ATT&CK.

> Crabs walk sideways. So do attackers.

**[Live demo](https://ilkerunver00.github.io/crabwalk/)** — the attack story, the
report, the interactive attack-path graph and an ATT&CK Navigator heatmap, rebuilt
from the bundled demo logs on every push.

![crabwalk HTML report](https://raw.githubusercontent.com/IlkerUnver00/crabwalk/main/docs/report-screenshot.png)

*The `crabwalk hunt --report` output for the bundled demo logs (recordings from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)): what
happened, step by step, with its own caveats, then the attack paths it reconstructed;
below the fold, ATT&CK coverage, a per-host timeline and ranked findings.*

## Try it in 30 seconds

The repository ships nine small attack recordings in [`demo/`](demo) (GPL-3.0 data
from EVTX-ATTACK-SAMPLES; the code is MIT), so it finds something right after a clone:

```bash
git clone https://github.com/IlkerUnver00/crabwalk.git
cd crabwalk
pip install -e .
crabwalk hunt demo/evtx --report report.html --graph attack-paths.html --story story.md
```

14 findings, 4 critical. Among them, a renamed PsExec whose source machine
(`NLLT108334`) is recovered from the target's own share-access log, a DCSync, and a
multi-hop path `NLLT108334 → PC01 → WIN-77LTAPHIQ1R`, told as a [story](#the-attack-story).
[`demo/README.md`](demo/README.md) explains what each file shows.

## Documentation

- **[Write-up: renamed PsExec, seen only from the target](docs/writeups/01-renamed-psexec-source-host.md)**
  — a case worked end to end from one 5145 log: recovering the source host from
  pipe names, the ATT&CK mapping, next steps and what the log cannot prove.
- **[Detection reference](docs/DETECTIONS.md)** — every rule's data sources,
  logic, severity, tunables, an allowlist example, false positives, blind spots
  and the tests that prove it.
- **[How crabwalk compares](docs/COMPARISON.md)** — Chainsaw, Hayabusa,
  Zircolite, LogonTracer, DeepBlueCLI, APT-Hunter and EvtxECmd: what each one
  does, and when to use which.
- **[Sigma rules](sigma/)** — the per-event parts of CW-012 translated to Sigma
  for SIEM use, checked with pySigma and against the corpus, with what Sigma
  cannot express.

## Why

Every SOC/DFIR team answers the same question after an intrusion: *where did the
attacker land, and where did they go next?* Answering it means stitching together
4624/4672 logon patterns, RDP session chains, remote service installs, scheduled
tasks and WinRM/WMI execution across hosts. crabwalk automates that triage pass.

## Status / Roadmap

- [x] **Step 1** — EVTX parsing into a normalized, time-sorted event stream
      (curated catalog of ~50 lateral-movement-relevant event IDs across 10 channels)
- [x] **Step 2** — Logon session tracking: LogonId lifecycles per host, inbound
      remote-logon edges (4624/RDP), outbound explicit-credential edges (4648),
      privilege backfill from 4672
- [x] **Step 3** — Detection rules engine: 12 rules over the session/edge state
      (see table below), findings deduplicated and ranked, every finding tagged
      with ATT&CK technique IDs
- [x] **Step 4** — ATT&CK Navigator layer export (`--layer`): findings scored
      per technique, opens as a heatmap in the ATT&CK Navigator
- [x] **Step 5** — Self-contained HTML report (`--report`): stat tiles, severity
      bar, ATT&CK table, per-host swimlane timeline (inline SVG), movement table,
      ranked finding cards — one file, no external assets, light/dark aware
- [x] **Step 6** — Validation harness against EVTX-ATTACK-SAMPLES: a ground-truth
      corpus test (filename documents the technique, crabwalk must map it), plus a
      clean-parse smoke test over the whole corpus. Fixed two parser bugs it surfaced
      (null record timestamps, `#attributes` nesting) and added event-level dedup.
- [x] **Step 7** — MIT license, GitHub Actions CI (test matrix on Python
      3.10–3.12), `.gitattributes` line-ending normalization, docs
- [x] **Step 8** — Damaged evidence never aborts a run: unopenable files (zero
      bytes, locked, not EVTX) and unreadable records are reported and skipped
- [x] **Step 9** — CW-012 named-pipe remote execution over Sysmon 17/18 *and*
      Security 5145, recovering the attacker's source host from PsExec pipe names
- [x] **Step 10** — Attack-path graph (`--graph`, and in the report): one node per
      machine, movement and source-aware findings as directed edges
- [x] **Step 11** — Tuning layer (`--config`): rule selection, tunable correlation
      windows, and an allowlist where every suppression carries a reason and can
      expire; suppressed findings stay visible
- [x] **Step 12** — Live demo: nine bundled recordings, a GitHub Pages site
      rebuilt on every push (report, attack-path graph, ATT&CK Navigator heatmap)
- [x] **Step 13** — Documentation: a detection reference, a case write-up, a
      comparison with other tools, and Sigma translations of the CW-012 signals
- [x] **Step 14** — Attack story (`--story`, report, live demo): the graph and the
      findings told as dated steps; one event, one finding (cross-rule merging)

## Quickstart

```bash
pip install -e .
crabwalk parse C:\evidence\logs --out timeline.jsonl
crabwalk sessions C:\evidence\logs --out sessions.json
crabwalk hunt C:\evidence\logs --out findings.json
crabwalk hunt C:\evidence\logs --report report.html --layer navigator.json
crabwalk hunt C:\evidence\logs --graph attack-paths.html --story story.md
crabwalk config --example > crabwalk.toml
crabwalk hunt C:\evidence\logs --config crabwalk.toml --show-suppressed
```

`parse` walks files or directories, keeps only the events that matter for
lateral movement (use `--all`, `--event-id`, `--channel` to override), prints a
triage summary and optionally writes a time-sorted JSONL stream.

`sessions` reconstructs logon sessions and prints host-to-host movement:

```text
sessions   : 20 total | 12 remote | 3 privileged+remote
edges      : 13 shown (2 machine-account edges hidden, --include-machine)

HOST-TO-HOST MOVEMENT
2019-03-18 11:27:23Z  EXAMPLE.CORP\administrator  PC01.example.corp -> WIN-77LTAPHIQ1R.example.corp  explicit-credentials
2019-03-19 00:02:04Z  EXAMPLE\Administrator       10.0.2.17         -> WIN-77LTAPHIQ1R.example.corp  network priv
```

`hunt` runs every detection rule and prints ranked findings. Against the
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
dataset (278 files, 37k records) it produces 72 findings across 11 techniques,
including wmiexec's `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\..` signature,
`sekurlsa::pth` logons, an LSASS dump launched through WMI, and a renamed PsExec
whose source machine is recovered from the target's own share-access log:

```text
[CRITICAL] 2019-01-19 13:00:10Z  CW-012  Remote execution over named pipes
    host: IEWIN7   user: IEWIN7\IEUser   ATT&CK: T1021.002, T1569.002, T1570
    PsExec-style stdio pipes: \blabla-NLLT108334-37048-stderr, ...; from 10.0.2.16;
    service 'blabla' (renamed) launched from host NLLT108334 (pid 37048);
    after 'blabla.exe' was written to \\*\ADMIN$

[HIGH] 2019-08-30 12:54:08Z  CW-006  Process spawned via WMI
    host: MSEDGEWIN10   user: MSEDGEWIN10\IEUser   ATT&CK: T1047
    WmiPrvSE.exe (WMI) spawned 'rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 ...'
```

**One event, one finding.** When another rule's finding already cites every
record of a finding, claims its techniques at no lower severity, and names the
same host, account, source and time, the smaller one is listed under it ("also
matched") instead of as a second finding: the ADMIN$ drop CW-005 reports is the
same record CW-012 credits to that PsExec run. Two rules that disagree about
who did it, or from where, stay two findings.

## The attack story

After the findings, `hunt` tells what happened, in order: one path per connected
group of hosts, one dated line per step from host to host or per burst of findings
on a host, as whom, from where. The same story leads the HTML report and the
[live demo](https://ilkerunver00.github.io/crabwalk/); `--story FILE.md` writes it
as Markdown for a ticket or case file, and `--out` adds it to the JSON. From the
demo logs:

```text
Path 1: NLLT108334 -> PC01.example.corp -> WIN-77LTAPHIQ1R.example.corp (also: IEWIN7)
  4 hosts · 2019-01-19 to 2019-04-30 · started from NLLT108334 · worst finding: critical
  CAUTION: this path has gaps of 28 days, 29 days and 42 days. crabwalk links these hosts only
  because they share host names and addresses; it has no case or incident ID, so confirm that
  the steps belong to one intrusion before reporting them as one.
  2019-01-19 13:00:10Z  NLLT108334 (10.0.2.16) -> IEWIN7 as IEWIN7\IEUser: copied 'blabla.exe'
      to ADMIN$, then ran it through PsExec with its service renamed to 'blabla'  [critical CW-012]
  2019-02-16 17:54:41Z–17:57:55Z  (28 days later) 10.0.2.16 (named NLLT108334 elsewhere in the
      logs) -> PC01.example.corp as PC01\IEUser: copied 'System32\RemComSvc.exe' to ADMIN$, then
      used the service control manager remotely (svcctl)  [critical CW-012]
  ...
  2019-03-18 11:06:29Z  on PC01.example.corp as EXAMPLE\user01: started a process with injected
      credentials (logon type 9 via seclogo: the sekurlsa::pth pattern)  [high CW-003]
  2019-03-18 11:27:23Z  PC01.example.corp -> WIN-77LTAPHIQ1R.example.corp as EXAMPLE\Administrator:
      used explicit credentials (4648) 3 times
  ...
```

It is generated, not written: every line is a movement step on a graph edge or
a burst of one rule's findings, so it traces back to findings and their records.
It is written to say what the records show and no more:

- **Sources as the step saw them.** A step names its source the way its own
  records do; a name learned from other records is said to be ("10.0.2.16 (named
  NLLT108334 elsewhere in the logs)"). External addresses are marked, and remote
  activity with no named source says so.
- **Each record once, each time shown.** A logon a finding already cites is not
  counted again, anonymous null sessions are not counted as admin logons, a line
  that spans time shows the span, and a repeat later on is its own line.
- **Accounts by identity.** One account is one name across the story, joined by
  SID where the records give one (never for local accounts: hosts cloned from one
  image share local SIDs).
- **Doubt up front.** Gaps of more than a day are marked, and a path with
  week-long gaps gets a caution before its steps: crabwalk links hosts by name
  and address, not by case. Findings with a null (1601) time are counted, not
  placed.

## Attack paths

`crabwalk hunt --graph FILE` writes the reconstructed intrusion as a graph, in the
format the extension asks for: `.html` (standalone page — hover or click a host to
focus its paths), `.dot`/`.gv` (Graphviz) or `.json` (nodes/edges for Cytoscape,
vis.js, …). The HTML report embeds the same graph.

- **One node per machine.** Logs name the same box as `WIN-1.corp.local`,
  `WIN-1`, `10.0.2.17`, `::ffff:10.0.2.17` or `WIN-1$`; addresses are mapped to
  names wherever the evidence pairs them (4624 `IpAddress` + `WorkstationName`).
  That also stitches the two halves of a hop together: the 4648 logged on the
  source and the 4624 logged on the target become one edge.
- **Edges are movement.** Logons and RDP sessions from the session layer, plus
  every finding that knows its source — a 5145 client address, or the host
  PsExec wrote into its pipe names. Edge color is the worst finding on it; dashed
  edges are plain logons.
- **Read left to right.** Hosts are layered by longest path, with cycles broken
  in time order, so origin → hop → target lines up; origins are labeled.

## Tuning and allowlisting

Every environment has backup agents, deployment tools and admins whose normal work
looks like lateral movement. A TOML file tunes crabwalk to it without code changes:

```toml
[rules]
disable = ["CW-009"]          # or: only = ["CW-012", "CW-001"]
min_severity = "medium"

[rules.CW-003]
privileged_ntlm = false       # keep the sekurlsa::pth signature, drop the noisy half

[rules.CW-012]
cluster_gap = "3m"

[[allow]]
reason = "SCCM client push installs ccmsetup"   # required
rules = ["CW-001", "CW-005", "CW-012"]          # optional, default all rules
users = ["CORP\\svc_sccm"]                      # globs; a bare name matches any domain
sources = ["10.0.5.0/24"]                       # client IP/CIDR, or source host glob
expires = 2026-12-31                            # optional: allowlists rot
[[allow.fields]]                                # the install (System 7045)
ServiceName = "^ccmsetup$"
ImagePath = '^"?C:\\Windows\\ccmsetup\\ccmsetup\.exe"?( |$)'
[[allow.fields]]                                # the binary copied to ADMIN$ (5145)
ShareName = '\\ADMIN\$$'
RelativeTargetName = '^ccmsetup\\ccmsetup\.exe$'
[[allow.fields]]                                # the SCM pipe, opened on IPC$ (5145)
ShareName = '\\IPC\$$'
RelativeTargetName = '^svcctl$'
```

Each evidence record of a finding must match one `[[allow.fields]]` table. Pin
what the record *is* (the service's binary, the share, the pipe), not only names
an attacker can reuse: a service called `ccmsetup` whose image is a PowerShell
command line, or the same file dropped over `C$`, stays visible. Names and paths
cannot tell a trojaned `ccmsetup.exe` from the real one, so keep `users` and
`sources` narrow too.

- **Generated, never stale.** `crabwalk config --example` prints every rule's
  tunables with their defaults, read from the rules themselves, all commented
  out. `crabwalk config FILE` validates a file and shows what will apply.
- **Strict.** Unknown keys, rule ids, CIDRs and regexes are errors with a
  pointer to the offending line. A typo in a suppression list must never pass
  quietly. A CIDR with host bits (`10.0.5.0/2`) is refused rather than widened,
  and an address-shaped typo (`10.0.5.300`) is refused rather than kept as a
  host glob that never matches. A correlation window of zero, which could never
  fire, is refused too. An `[[allow]]` entry needs a reason and at least
  one criterion; silencing a rule outright is what `disable` is for.
- **Narrow by construction.** With `fields`, *every* evidence event of a finding
  must match one of the entry's tables: carry all of that table's fields, each
  matching its regex. One benign event cannot excuse the rest of a finding; an
  entry written for `svcctl` polling cannot excuse the service install that
  escalated the same finding; and a misspelled or misplaced field makes its
  table match nothing, so the entry fails closed. Every table must name a field
  that says what a record is (`ServiceName`, `ImagePath`, `RelativeTargetName`,
  `PipeName`, `TaskContent`, `CommandLine`, `ScriptBlockText`, ...); who/where
  fields and per-type constants (`SubjectUserName`, `User`, `IpAddress`,
  `AccountName`, `ObjectType`) may only narrow it, since `users`, `hosts` and
  `sources` are for who and where. A table without one, an empty table, or a
  regex that accepts any value is refused when the file is read. `hunt` warns
  about near misses: the evidence an entry left out, and a table whose fields no
  record carries together (a misspelled narrowing field). Field names are
  case-insensitive. A NetBIOS-qualified user (`CORP\svc`) matches every
  notation of that domain (`CORP.LOCAL\svc`, `svc@corp.local`). A DNS realm
  (`svc@corp.contoso.com`) is compared whole against records that show a realm;
  against a record that shows only a NetBIOS domain (`CORP\svc`) it matches
  through the realm's first label, and only when written without globs. A
  qualified pattern never matches a record that does not show its domain (a
  bare name, a SID), and a bare name matches any domain. Where a domain's
  NetBIOS name is not the first label of its DNS name, list both forms.
- **Nothing disappears silently.** Suppressed findings are counted on the
  console (`--show-suppressed` lists them), written to the JSON output with the
  allow entry that matched, and listed in the HTML report. An entry suppresses a
  finding only if it also matches each finding merged into it, by that finding's
  own rule, account and source; otherwise the finding is kept and `hunt` says
  which rule the entry left out. Expired entries are
  reported and not applied. The JSON also records the effective settings next
  to the findings they produced.
- Command-line flags layer over the file: `--rule ID` (run only), `--disable ID`,
  `--min-severity LEVEL`.

## Detection rules

| Rule | Title | ATT&CK | Notes |
|---|---|---|---|
| CW-001 | Remote logon followed by service install | T1021.002, T1543.003 | PsExec pattern; known tool service names → critical |
| CW-002 | RDP chain across hosts | T1021.001 | A→B→C graph walk with hostname/IP correlation |
| CW-003 | Pass-the-hash indicators | T1550.002 | `seclogo`/LT9 signature; privileged NTLM network logons |
| CW-004 | Scheduled task from remote session | T1053.005 | 4698/4702 tied to a remote LogonId |
| CW-005 | Executable on administrative share | T1021.002, T1570 | ADMIN$/C$ + executable payloads |
| CW-006 | Process spawned via WMI | T1047 | WmiPrvSE children; shells → high |
| CW-007 | Remote execution via WinRM | T1021.006 | wsmprovhost children + WinRM event 91 |
| CW-008 | Suspicious PowerShell script block | T1059.001 | cradles, base64+IEX, Mimikatz, AMSI bypass |
| CW-009 | Event log cleared | T1070.001 | Security 1102, System 104 |
| CW-010 | Kerberoasting (RC4 service ticket) | T1558.003 | 4769 with RC4 (0x17) downgrade, non-machine SPN |
| CW-011 | DCSync (directory replication) | T1003.006 | 4662 replication GUID by a non-DC principal |
| CW-012 | Remote execution over named pipes | T1021.002, T1569.002 (+T1543.003, T1053.005, T1570) | Sysmon 17/18 + 5145 IPC$: tool pipes (PsExec, RemCom/impacket, PAExec, CSExec, Cobalt Strike), PsExec stdio pipes naming the source host, remote svcctl/ntsvcs/atsvc corroborated by a service install, task or ADMIN$ drop. Clustered per client, so concurrent sources stay apart; a client's own pipe sweep is suppressed; a tool client running on the host itself is reported as *local* execution, not lateral movement |

## Design notes

- **Minimal dependencies.** DFIR workstations are often offline; the only runtime
  dependency is the Rust-backed [`evtx`](https://github.com/omerbenamram/pyevtx-rs)
  parser (plus `tomli` on Python 3.10 only, where `tomllib` is not yet stdlib).
- **Dirty inputs are normal.** A file that cannot be opened (zero bytes, locked,
  not EVTX) or a record that cannot be read is counted and reported, never fatal;
  the run only exits non-zero when nothing at all could be read.
- **UTC everywhere.** Every timestamp is normalized to UTC at parse time.
- **Related work:** [Chainsaw](https://github.com/WithSecureOpenSource/chainsaw) and
  [Hayabusa](https://github.com/Yamato-Security/hayabusa) run thousands of Sigma
  rules over EVTX and are the right first pass over unknown evidence;
  [LogonTracer](https://github.com/JPCERTCC/LogonTracer) graphs accounts to hosts
  in Neo4j. crabwalk is narrower: stateful, cross-host correlation of lateral
  movement into a host-to-host path, meant to run alongside a Sigma engine.
  [COMPARISON.md](docs/COMPARISON.md) has the details and sources.

## ATT&CK coverage

Only the data a rule actually reads is listed. Other cataloged events (4625, 4776,
5140, RCM 1149, WinRM 168, WMI-Activity 5857–5861, PowerShell 4103, ...) show up in
`crabwalk parse` but feed no rule yet; [DETECTIONS.md](docs/DETECTIONS.md#scope) has
the full list.

| Technique | Name | Rules | Data crabwalk reads |
|---|---|---|---|
| T1021.001 | Remote Desktop Protocol | CW-002 | RDP chains A→B→C from 4624 LT10 and TS-LSM 21/25 |
| T1021.002 | SMB / Admin Shares | CW-001, CW-005, CW-012 | remote logon + service install; 5145 on ADMIN$/C$ and IPC$; Sysmon 17/18 |
| T1021.006 | WinRM | CW-007 | wsmprovhost child processes (Sysmon 1, 4688), WinRM/Operational 91 |
| T1047 | WMI | CW-006 | WmiPrvSE child processes (Sysmon 1, 4688) |
| T1053.005 | Scheduled Task | CW-004, CW-012 | 4698/4702 tied to a remote LogonId; remote atsvc access + task |
| T1543.003 | Windows Service | CW-001, CW-012 | 7045/4697/Sysmon 13 after a remote logon or credited to a pipe cluster |
| T1569.002 | Service Execution | CW-012 | remote-exec tool pipes, remote svcctl/ntsvcs access (Sysmon 17/18, 5145 IPC$) |
| T1570 | Lateral Tool Transfer | CW-005, CW-012 | executables reached on ADMIN$/C$ (5145) |
| T1550.002 | Pass the Hash | CW-003 | 4624 LT9 `seclogo` signature; privileged (4672) NTLM network logons |
| T1558.003 | Kerberoasting | CW-010 | 4769 with RC4 (0x17) tickets |
| T1003.006 | DCSync | CW-011 | 4662 replication rights by a non-DC principal |
| T1059.001 | PowerShell | CW-008 | 4104 script blocks (download cradles, IEX, base64 decode, Mimikatz, AMSI bypass) |
| T1070.001 | Clear Windows Event Logs | CW-009 | Security 1102, System 104 |

## Validation

crabwalk is regression-tested against a ground-truth corpus
([EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)). Each
entry is a sample whose filename names the technique it demonstrates — e.g.
`LM_renamed_psexecsvc_5145.evtx` (T1021.002), `sysmon_10_1_memdump_comsvcs_minidump.evtx`
(T1047), `DE_1102_security_log_cleared.evtx` (T1070.001) — and the test asserts
crabwalk maps it correctly. Precision is tested too: a negative list pins samples
of *other* attacker activity that a rule must not mislabel (e.g. BloodHound and
pipe-enumeration sweeps must not trigger CW-012). One test proves the cross-host
claim end to end: from the target's own 5145 log, CW-012 recovers PsExec's source
as `NLLT108334` at `10.0.2.16`. A smoke test parses the entire corpus (37k+
records across 278 files) and fails on a single unreadable file or record.

The corpus is not vendored. Clone it and point the tests at it:

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git samples/EVTX-ATTACK-SAMPLES
pytest tests/test_corpus.py -v          # or set CRABWALK_SAMPLES=/path/to/clone
```

When the corpus is absent the corpus tests skip, so the unit suite runs anywhere.

## Development

```bash
pip install -e ".[dev]"
pytest        # unit tests always run; corpus tests skip without samples
```

## Packaging

Builds a standard wheel + sdist (hatchling); both pass `twine check`:

```bash
python -m build
twine check dist/*
# twine upload dist/*   # publish to PyPI (needs a PyPI account/token)
```
