# Benchmark: crabwalk, Hayabusa and Chainsaw on the same lateral-movement logs

[COMPARISON.md](COMPARISON.md) compares the three tools on what their documentation says.
This page runs them. Each tool went over the same 47 recordings with the rules its release
ships, and the same yardstick was applied to all three outputs. The raw per-file numbers are
in [`benchmark/results.json`](benchmark/results.json). [`scripts/benchmark.py`](../scripts/benchmark.py)
reproduces them.

**Read this first.** crabwalk's rules were written and validated against this same corpus
([DETECTIONS.md](DETECTIONS.md#how-the-rules-are-validated)). Hayabusa's and Chainsaw's were
not tuned to it. The setup therefore favours crabwalk wherever its rules apply, and the
numbers should be read that way. The samples are short lab recordings, one technique per
file, and the measure is coarse: did a tool raise an alert at medium or above, and was
that alert tagged as lateral movement.

## What was run

| | Version | Rules | Invocation (per file) |
|---|---|---|---|
| crabwalk | 0.1.0 (this repository) | 12 | `crabwalk hunt FILE` |
| Hayabusa | 4.1.0, `hayabusa-4.1.0-win-x64.zip` | 4,658 loaded (4,476 Sigma, 182 Hayabusa); noisy, deprecated and unsupported rules off, as shipped | `dfir-timeline -f FILE -w`, JSONL, `verbose` profile |
| Chainsaw | 2.16.5, `chainsaw_all_platforms+rules.zip` | 3,758 loaded (bundled Sigma + Chainsaw rules) | `hunt FILE -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/`, JSONL |

- **Data:** the 47 files of the `Lateral Movement` folder of
  [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), commit `4ceed2f`.
  Each file was run on its own.
- **Release integrity.** Both archives match the SHA-256 digests GitHub publishes for them. No
  rule update was run.
  - Hayabusa: `4d304cc5baaa750ed08cc24b7b89c58ea058740c7e344502d7b82554637543a8`
  - Chainsaw: `fbd5e12fbd70395bc7fdfdf2d3903e8545f27ca2f35e23059df6177641b76205`
- **Settings.** These are the tools' documented non-interactive runs, and both are broad.
  - Hayabusa's plain `dfir-timeline` starts an interactive wizard. `-w` skips it and scans
    with every rule level and status, including 366 experimental rules.
  - Chainsaw's documented `-s sigma/` loads SigmaHQ's whole tree, including its
    `deprecated/`, `unsupported/` and `other/` folders, which Hayabusa leaves off.
  - Both choices favour the engines' breadth. Their effect is given below each finding.
- **When and where:** run on 2026-10-08, Windows 11, Python 3.12.
- **Same yardstick for every tool:**
  - *medium+*: an alert at level medium, high or critical. Hayabusa's "emergency" counts as
    critical.
  - *lateral*: an alert tagged with the ATT&CK tactic lateral movement (TA0008), or with one
    of its techniques (T1021, T1570, T1550, T1563, T1210, T1534, T1080, T1072). crabwalk is
    judged by the techniques on its findings. The other two are judged by their rules' tags.

## Results

| Over the 47 files | crabwalk | Hayabusa 4.1.0 | Chainsaw 2.16.5 |
|---|---|---|---|
| Files with an alert at medium+ | 16 | **29** | 27 |
| Files with a *lateral* alert at medium+ | **10** | 8 | 6 |
| Alerts at medium+ | **34** | 130 | 110 |
| Alerts, all levels | 34 | 1,221 (1,038 informational) | 180 |
| Most alerts at medium+ in one file | 5 | 24 | 26 |

How the settings move these numbers:

- **Hayabusa without its experimental rules** (`-w --exclude-status experimental`):
  27 files at medium+, 7 with a lateral alert, 107 alerts at medium+.
- **Chainsaw without SigmaHQ's `deprecated/`, `unsupported/` and `other/` rules:**
  - 154 alerts in all, 101 at medium+, at most 23 in one file;
  - no file changes status.

**Breadth goes to the rule engines.** Hayabusa raised a medium+ alert on 29 files and Chainsaw
on 27; crabwalk did on 16. crabwalk stays silent on 18 files that Hayabusa or Chainsaw flag,
almost all of them techniques it has no rule for:

- DCOM (LethalHTA, MMC20 via impacket);
- SharpRDP and RDP `tsclient` startup-folder drops;
- WinRM through `winrshost.exe` (crabwalk's CW-007 knows `wsmprovhost.exe`);
- PsExec seen only through Sysmon process creation;
- an IIS web shell, MSSQL `xp_cmdshell` and remote registry;
- unsigned DLLs loaded into LSASS;
- a pipe added to the null-session registry list;
- a local pass-the-hash seen through Sysmon;
- a service install seen only in the System log, with no logon to tie it to.

Hayabusa or Chainsaw flag those, mostly through Sysmon process, image-load and registry rules.
For unknown evidence, start with one of them.

**Target-side share and WinRM logs go to crabwalk.** On five files, crabwalk raised a medium+
alert and neither other tool did. Four are a target host's Security log of share access
(5145); one is its WinRM/Operational log:

| File | crabwalk | Hayabusa | Chainsaw |
|---|---|---|---|
| `LM_renamed_psexecsvc_5145.evtx` | critical: renamed PsExec, source host NLLT108334 recovered from the pipe names | 2 informational (*NetShare File Access*) | none |
| `LM_5145_Remote_FileCopy.evtx` | 5 high: executables accessed on `C$`, two of them written (`setup.bat`, `malwr.exe`) | 853 informational (*NetShare File Access*) | none |
| `LM_REMCOM_5145_TargetHost.evtx` | critical: RemCom over `svcctl` after its binary was copied, plus a high | 20 informational | none |
| `LM_Remote_Service01_5145_svcctl.evtx` | medium: remote `svcctl` access | none | none |
| `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` | medium: WinRM shell started (WinRM/Operational 91) | none | none |

**The lateral row measures tagging as much as detection.** crabwalk flagged 10 files with a
lateral alert, Hayabusa 8 and Chainsaw 6. Of the files where only crabwalk has one, two are
files where the engines also alert at medium+, just under other tags:

- `lm_sysmon_18_remshell_over_namedpipe.evtx`: all three alert on the same Sysmon 18 record.
  crabwalk's is medium, as remote execution over named pipes (T1021.002). Hayabusa and
  Chainsaw rate it critical as *Malicious Named Pipe Created*, tagged privilege escalation.
- `LM_ScheduledTask_ATSVC_target_host.evtx`, the atexec-style task:
  - All three raise the log clear the file holds.
  - The engines' other medium+ alerts there are about reconnaissance (*Password Policy
    Enumerated*, *AD Privileged Users or Groups Reconnaissance*).
  - Hayabusa also logs the task's creation and the admin logons, at informational level.
  - crabwalk rates them medium+: the remote `atsvc` task registration (CW-012), and the NTLM
    admin logons as pass-the-hash indicators (CW-003).

**Volume.** At medium+, crabwalk raised 34 alerts, Hayabusa 130 and Chainsaw 110. Of
Hayabusa's 1,221 alerts at all levels, 1,038 are informational. 853 of those come from one
file, because Hayabusa logs every file access on a non-`IPC$` share at informational level.
Part of the gap is by design. A rule engine reports events one at a time, while crabwalk
correlates them into findings: one CW-012 finding cites the share access, the pipe opens and
the install of one PsExec run.

## Cases

**A renamed PsExec, seen only from the target (`LM_renamed_psexecsvc_5145.evtx`).** SigmaHQ
has a rule written for exactly this sample, *Suspicious PsExec Execution*, and both engines
ship it. Neither raises it, as shipped. The rule's `ShareName` value escapes a literal `*`
(`\\\\\*\\IPC$`, meaning the string `\\*\IPC$`). In a copy of the rule whose `ShareName` line
reads `ShareName|endswith: 'IPC$'`, both engines fire on the same three stdio-pipe records
(EventRecordID 84050 to 84052, records 20 to 22 in the write-up's numbering). So the miss is
in how the escaped value is matched, not missing coverage. crabwalk reports the run as
critical and names the source host, NLLT108334 at 10.0.2.16. The
[write-up](writeups/01-renamed-psexec-source-host.md) works this case end to end.

**PsExec run against its own host (`DE_renamed_psexec_service_sysmon_17_18.evtx`, from the
corpus's Defense Evasion folder).** crabwalk reports a medium *local* execution with no
lateral-movement technique: "ran PsExec against this same host … no other host involved".
Hayabusa reports 11 informational pipe events. Chainsaw reports nothing.

**Explicit credentials from PC01, network logons on WIN-77LTAPHIQ1R (`LM_WMIC_4648_rpcss.evtx`
and `LM_WMI_4624_4688_TargetHost.evtx`).**

- *The source-side file.* The rule engines do better here. Hayabusa and Chainsaw flag its 4648
  as *Suspicious Remote Logon with Explicit Credentials* (medium, lateral). crabwalk raises
  only the log clear the file also holds.
- *The target-side file.* All three stay below medium.
- *What crabwalk adds.* It draws the PC01 → WIN-77LTAPHIQ1R movement as a graph edge and a
  story step from either file alone, which neither engine does. Loaded together, the 4648
  (11:27Z) and the 4624s (22:15Z) land on that one edge as two dated steps about 11 hours
  apart. The records do not show that they are one hop.

**The nine demo recordings together (`demo/evtx`).** Over the demo set crabwalk raises 14
alerts, Hayabusa 125 and Chainsaw 57, of which Hayabusa and Chainsaw each rate 40 medium+.
Only crabwalk links hosts into a path, NLLT108334 → PC01 → WIN-77LTAPHIQ1R. That path shows
what the linking does, not proof of an intrusion:

- The NLLT108334 → PC01 link rests only on the address 10.0.2.16. It appears in two
  unrelated recordings four weeks apart, from a lab address range.
- The [live demo](https://ilkerunver00.github.io/crabwalk/)'s story says so itself: that
  step's source reads "10.0.2.16 (named NLLT108334 elsewhere in the logs)", and the path
  opens with a caution about its gaps.

## Speed, for context

Median of three runs over the whole corpus (278 files, 37,364 records) on the same machine,
each tool started as a process:

| crabwalk (`crabwalk hunt`) | Hayabusa | Chainsaw |
|---|---|---|
| 1.0 s | 6.5 s | 13.4 s |

Single runs varied by up to half: Chainsaw took 18.3 s once. This does not mean crabwalk is
faster at the same job:

- crabwalk keeps about 3,000 of the 37,364 records, the event IDs its 12 rules read, and
  evaluates 12 rules.
- The other two evaluate thousands of rules over every record.

The point is practical: crabwalk adds about a second to a triage run that already uses one
of them.

## What this does not show

- **Detection quality in the wild.** These are lab recordings, one technique each, so there
  are no false positives to count. The rule engines' alerts on these files are mostly true;
  their cost is volume.
- **Lateral movement as a whole.** The folder is one author's collection of 47 recordings,
  and many techniques appear once or not at all. Ten or so files of a technique crabwalk does
  not cover would move its numbers a lot.
- **Other settings.** The ranges above show how much the rule sets matter. A minimum level of
  low or medium would cut Hayabusa's alert count but not its medium+ counts.

## Reproduce

Download both releases from their GitHub pages, check the SHA-256 digests above, and unpack
them under `samples/tools/` (gitignored). Then run, one command per line:

```bash
git clone --depth 1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git samples/EVTX-ATTACK-SAMPLES
python scripts/benchmark.py --samples samples/EVTX-ATTACK-SAMPLES --hayabusa samples/tools/hayabusa --chainsaw samples/tools/chainsaw/chainsaw
```

The script reads every tool's output from stdout and writes only counts, levels, rule titles
and tags. The samples contain real malware command lines, which the tools copy into their
output, and antivirus software flags such files. A run takes a few minutes, about 2 s per
file each for Hayabusa and Chainsaw. The timings above came from separate runs.
