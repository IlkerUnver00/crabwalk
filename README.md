# crabwalk

[![CI](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml/badge.svg)](https://github.com/IlkerUnver00/crabwalk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

**Windows EVTX lateral movement hunter** — parses Windows event logs, correlates
logon/service/scheduled-task/PowerShell activity into an attack timeline, and maps
every finding to MITRE ATT&CK.

> Crabs walk sideways. So do attackers.

![crabwalk HTML report](https://raw.githubusercontent.com/IlkerUnver00/crabwalk/main/docs/report-screenshot.png)

*The `crabwalk hunt --report` output: severity summary, ATT&CK coverage, and a
per-host timeline — here over the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
corpus.*

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
- [x] **Step 3** — Detection rules engine: 11 rules over the session/edge state
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

## Quickstart

```bash
pip install -e .
crabwalk parse C:\evidence\logs --out timeline.jsonl
crabwalk sessions C:\evidence\logs --out sessions.json
crabwalk hunt C:\evidence\logs --out findings.json
crabwalk hunt C:\evidence\logs --report report.html --layer navigator.json
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
dataset (278 files, 37k records) it produces 66 findings across 9 techniques,
including wmiexec's `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\..` signature,
`sekurlsa::pth` logons and an LSASS dump launched through WMI:

```text
[HIGH] 2019-08-30 12:54:08Z  CW-006  Process spawned via WMI
    host: MSEDGEWIN10   user: MSEDGEWIN10\IEUser   ATT&CK: T1047
    WmiPrvSE.exe (WMI) spawned 'rundll32 C:\windows\system32\comsvcs.dll, MiniDump 4868 ...'
```

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

## Design notes

- **Minimal dependencies.** DFIR workstations are often offline; the only runtime
  dependency is the Rust-backed [`evtx`](https://github.com/omerbenamram/pyevtx-rs)
  parser.
- **Dirty inputs are normal.** Unparsable records are counted and reported, never fatal.
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
| T1543.003 | Windows Service | 7045/4697 shortly after a network logon (PsExec pattern) |
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
crabwalk maps it correctly. A separate smoke test parses the entire corpus (37k+
records across 278 files) and fails on a single unparsable record.

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
