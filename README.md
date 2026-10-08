# crabwalk

[![CI](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml/badge.svg)](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Windows EVTX lateral movement hunter** — parses Windows event logs, correlates
logon/service/scheduled-task/named-pipe/PowerShell activity across hosts, draws the
result as an **attack-path graph**, and maps every finding to MITRE ATT&CK.

> Crabs walk sideways. So do attackers.

![crabwalk HTML report](https://raw.githubusercontent.com/IlkerUnver00/crabwalk/main/docs/report-screenshot.png)

*The `crabwalk hunt --report` output over the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
corpus: the attack paths it reconstructed (who moved where, how, and what fired on
each host), then severity, ATT&CK coverage, a per-host timeline and ranked findings.*

## Why

Every SOC/DFIR team answers the same question after an intrusion: *where did the
attacker land, and where did they go next?* Answering it means stitching together
4624/4672 logon patterns, RDP session chains, remote service installs, scheduled
tasks and WinRM/WMI execution across hosts. crabwalk automates that triage pass.

## Status / Roadmap

- [x] **Step 1** — EVTX parsing into a normalized, time-sorted event stream
      (curated catalog of ~45 lateral-movement-relevant event IDs across 10 channels)
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

## Quickstart

```bash
pip install -e .
crabwalk parse C:\evidence\logs --out timeline.jsonl
crabwalk sessions C:\evidence\logs --out sessions.json
crabwalk hunt C:\evidence\logs --out findings.json
crabwalk hunt C:\evidence\logs --report report.html --layer navigator.json
crabwalk hunt C:\evidence\logs --graph attack-paths.html
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
dataset (278 files, 37k records) it produces 74 findings across 11 techniques,
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
rules = ["CW-001", "CW-012"]                    # optional, default all rules
users = ["CORP\\svc_sccm"]                      # globs; a bare name matches any domain
sources = ["10.0.5.0/24"]                       # client IP/CIDR, or source host glob
expires = 2026-12-31                            # optional: allowlists rot
[allow.fields]                                  # regex on the evidence events
ServiceName = "^ccmsetup$"
```

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
- **Narrow by construction.** A field regex must hold for *every* evidence event
  that carries the field, so one benign event cannot excuse the rest of a
  finding. A NetBIOS-qualified user (`CORP\svc`) matches every notation of that
  domain (`CORP.LOCAL\svc`, `svc@corp.local`). A DNS realm (`svc@corp.contoso.com`)
  is compared whole, so it never reaches into another forest. A qualified pattern
  never matches a record that does not show its domain (a bare name, a SID), and
  a bare name matches any domain. Where a domain's NetBIOS name is not the first
  label of its DNS name, list both forms. Field names are case-insensitive, and a
  field name that occurs in none of the evidence it is meant to match is reported
  as a likely typo.
- **Nothing disappears silently.** Suppressed findings are counted on the
  console (`--show-suppressed` lists them), written to the JSON output with the
  allow entry that matched, and listed in the HTML report. Expired entries are
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
- **Related work:** [Chainsaw](https://github.com/WithSecureLabs/chainsaw) and
  [Hayabusa](https://github.com/Yamato-Security/hayabusa) run generic Sigma rules
  over EVTX per-event. crabwalk is narrower and deeper: stateful, cross-host
  correlation of lateral movement (session chains), not signature matching.

## ATT&CK coverage

| Technique | Name | Detection idea |
|---|---|---|
| T1021.001 | Remote Desktop Protocol | RDP session chains (4624 LT10, TS-LSM 21/25, RCM 1149) |
| T1021.002 | SMB / Admin Shares | 5140/5145 on ADMIN$/C$ + service/task creation |
| T1021.006 | WinRM | WinRM/Operational 91/168 + wsmprovhost lineage |
| T1047 | WMI | WMI-Activity 5857–5861, wmiprvse child processes |
| T1053.005 | Scheduled Task | 4698/4702 shortly after a network logon |
| T1543.003 | Windows Service | 7045/4697/Sysmon 13 shortly after a network logon or SCM pipe access |
| T1569.002 | Service Execution | remote-exec tool pipes, remote svcctl/ntsvcs access (Sysmon 17/18, 5145 IPC$) |
| T1550.002 | Pass the Hash | 4624 LT3 + NTLM anomalies, 4776 patterns |
| T1558.003 | Kerberoasting | 4769 with RC4 (0x17) encryption downgrade |
| T1003.006 | DCSync | 4662 replication rights by a non-DC principal |
| T1059.001 | PowerShell | 4103/4104 script blocks (encoded / download cradles) |
| T1070.001 | Clear Windows Event Logs | Security 1102, System 104 |

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
