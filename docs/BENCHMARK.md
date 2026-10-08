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
| crabwalk | 0.1.0 (this repository): commit `9d23709` for the first run, the current one for "now" | 12, now 15 | `crabwalk hunt FILE` |
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

The first run measured crabwalk at commit `9d23709` (12 rules). The rules added since,
CW-013 to CW-015 and `winrs` in CW-007, were written from the files this run showed crabwalk
missing, so the "crabwalk now" column is a score on the data they were built from, not a
test of them. The [second corpus](#a-second-corpus-the-rules-never-saw) is that test.

| Over the 47 files | crabwalk, first run | crabwalk now | Hayabusa 4.1.0 | Chainsaw 2.16.5 |
|---|---|---|---|---|
| Files with an alert at medium+ | 16 | 22 | **29** | 27 |
| Files with a *lateral* alert at medium+ | 10 | **16** | 8 | 6 |
| Alerts at medium+ | **34** | 41 | 130 | 110 |
| Alerts, all levels | 34 | 41 | 1,221 (1,038 informational) | 180 |
| Most alerts at medium+ in one file | 5 | 5 | 24 | 26 |

A rerun of the two engines on the same files gave the same numbers. How the settings move
them:

- **Hayabusa without its experimental rules** (`-w --exclude-status experimental`):
  27 files at medium+, 7 with a lateral alert, 107 alerts at medium+.
- **Chainsaw without SigmaHQ's `deprecated/`, `unsupported/` and `other/` rules:**
  - 154 alerts in all, 101 at medium+, at most 23 in one file;
  - no file changes status.

**Breadth goes to the rule engines.** Hayabusa raised a medium+ alert on 29 files and Chainsaw
on 27; crabwalk did on 16 in the first run. It stayed silent on 18 files that Hayabusa or
Chainsaw flag, almost all of them techniques it had no rule for:

- DCOM (LethalHTA, MMC20 via impacket): now CW-013;
- RDP `tsclient` startup-folder drops and a SharpRDP run from `\\tsclient`: now CW-014 and
  CW-015; a startup-folder write over SMB: CW-014;
- WinRM through `winrshost.exe`: now in CW-007, which knew only `wsmprovhost.exe`;
- the other SharpRDP sample, which types its command into the Run dialog;
- PsExec seen only through Sysmon process creation;
- an IIS web shell, MSSQL `xp_cmdshell` and remote registry;
- unsigned DLLs loaded into LSASS;
- a pipe added to the null-session registry list;
- a local pass-the-hash seen through Sysmon;
- a service install seen only in the System log, with no logon to tie it to.

Twelve of those files are still engine-only. Hayabusa or Chainsaw flag them, mostly through
Sysmon process, image-load and registry rules. For unknown evidence, start with one of them.

**Target-side share and WinRM logs go to crabwalk.** On five files, crabwalk raised a medium+
alert and neither other tool did, in both runs. Four are a target host's Security log of
share access (5145); one is its WinRM/Operational log:

| File | crabwalk | Hayabusa | Chainsaw |
|---|---|---|---|
| `LM_renamed_psexecsvc_5145.evtx` | critical: renamed PsExec, source host NLLT108334 recovered from the pipe names | 2 informational (*NetShare File Access*) | none |
| `LM_5145_Remote_FileCopy.evtx` | 5 high: executables accessed on `C$`, two of them written (`setup.bat`, `malwr.exe`) | 853 informational (*NetShare File Access*) | none |
| `LM_REMCOM_5145_TargetHost.evtx` | critical: RemCom over `svcctl` after its binary was copied, plus a high | 20 informational | none |
| `LM_Remote_Service01_5145_svcctl.evtx` | medium: remote `svcctl` access | none | none |
| `LM_winrm_target_wrmlogs_91_wsmanShellStarted_poorLog.evtx` | medium: WinRM shell started (WinRM/Operational 91) | none | none |

**The lateral row measures tagging as much as detection.** In the first run crabwalk flagged
10 files with a lateral alert, Hayabusa 8 and Chainsaw 6. Of the files where only crabwalk
had one, two are files where the engines also alert at medium+, just under other tags:

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

**Volume.** At medium+, crabwalk raised 34 alerts in the first run (41 now), Hayabusa 130 and
Chainsaw 110. Of Hayabusa's 1,221 alerts at all levels, 1,038 are informational. 853 of those
come from one file, because Hayabusa logs every file access on a non-`IPC$` share at
informational level. Part of the gap is by design. A rule engine reports events one at a
time, while crabwalk correlates them into findings: one CW-012 finding cites the share
access, the pipe opens and the install of one PsExec run.

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

**The nine demo recordings together (`demo/evtx`).** Over the demo set crabwalk raises 13
alerts (14 in the first run, before CW-003 grouped a burst), Hayabusa 125 and Chainsaw 57, of which Hayabusa and Chainsaw each rate 40 medium+.
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

- crabwalk keeps about 3,000 of the 37,364 records, the event IDs its rules read, and
  evaluated 12 rules at the time (15 now).
- The other two evaluate thousands of rules over every record.

The point is practical: crabwalk adds about a second to a triage run that already uses one
of them.

## A second corpus the rules never saw

Everything above runs on the corpus crabwalk's rules were written on. To see what that is
worth, the same three tools ran over a second one:
[EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) by
mdecrevoisier (CC0, commit `4748560`). It has 293 recordings: 280 in one folder per ATT&CK
tactic, 18 of them under `TA0008-Lateral Movement`; 11 attack steps in one lab domain under
`EVTX_full_APT_attack_steps`; and 2 Defender logs. No crabwalk rule was written against it. By content the two
corpora share one file, a SID-history sample outside lateral movement. For the engines it is
not unseen: Hayabusa's own sample collection,
[hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx), includes
both corpora.

**How it was run.**

1. **Blind.** All 293 files, each on its own, with crabwalk at commit `9d23709`, the version
   measured above, before any of the corpus's records were read. Raw numbers:
   [`benchmark/results-evtx-to-mitre-attack-blind.json`](benchmark/results-evtx-to-mitre-attack-blind.json).
2. **Then** the misses and the wrong alerts were read, and crabwalk changed. Each change is
   listed below with what led to it.
3. **Again.** crabwalk alone was rerun on the same files; the engines' rows were kept
   (`--reuse`): [`benchmark/results-evtx-to-mitre-attack.json`](benchmark/results-evtx-to-mitre-attack.json).

**Blind results.**

| | crabwalk | Hayabusa 4.1.0 | Chainsaw 2.16.5 |
|---|---|---|---|
| `TA0008-Lateral Movement` (18 files): files with an alert at medium+ | 4 | **11** | 7 |
| ... files with a *lateral* alert at medium+ | 3 | **6** | 5 |
| ... alerts at medium+ | 5 | 130 | 13 |
| `EVTX_full_APT_attack_steps` (11 files): files with a *lateral* alert at medium+ | **7** | **7** | 4 |
| All 293 files: files with an alert at medium+ | 53 | **148** | 117 |
| ... files with a *lateral* alert at medium+ | 17 | **27** | 15 |
| ... alerts at medium+ | 180 | 2,000 | 1,352 |
| ... alerts, all levels | 180 | 7,860 | 1,903 |

**On unseen data the lateral-movement lead is gone.** In the lateral-movement folder crabwalk
raised a lateral alert on 3 of 18 files, Hayabusa on 6 and Chainsaw on 5. What crabwalk
missed and an engine caught:

- RDP session hijacking with `tscon` (two files, both engines);
- an RDP logon denied to a valid account (4825, both engines);
- an MMC20 DCOM activation seen in 4688 (Hayabusa);
- an OpenSSH server listening (Hayabusa, which tags it lateral movement).

On the pass-the-hash file all three alert. Some files in that folder record preparation
rather than movement (a share created, a print share modified, a WS-Management listener
enumerated), and no tool raises a lateral alert on them.

**What it catches, it catches across the tactic folders.** Outside the lateral-movement
folder crabwalk raised lateral alerts on 14 files: remote execution and remote credential
theft over SMB filed under Execution and Credential Access (impacket's wmiexec, atexec and
secretsdump, lsassy, service creation over named pipes) and under the attack chains. One
was wrong: a PsExec run on its own host, reported as critical lateral movement (fixed
below). Hayabusa raised lateral alerts on 21 files outside the folder and Chainsaw on 10.
Both also tag that local PsExec file, through a rule that matches the PsExec binary starting.

**The attack steps are where linking shows.** Over the 11 step recordings together,
crabwalk joins 7 hosts into one path and puts a caution in front of it: the steps are up to
176 days apart and only share addresses and names. No engine output links hosts.

**What the second corpus changed.** Four changes came from reading its results:

| Change | What led to it | Effect on this corpus |
|---|---|---|
| CW-012: PsExec run against its own host is *local*, also when its service pipe is reached over SMB loopback | `PSexec as system execution` was reported as critical lateral movement. The first corpus's local sample used a renamed service, so its loopback connect never matched a tool pipe and the gap stayed hidden | that file: medium, local, no lateral technique |
| CW-003: one finding per burst of privileged NTLM logons (same source, account and host) | one run of 14 logons in 8 seconds gave 14 findings that differed only in their time | 180 alerts become 156 |
| CW-009: clearing every log at once is one finding (same host and account, each clear within a minute of the previous) | 91 log clears in one file gave 91 findings, one per channel: a System and a Security clear minutes apart, then 89 channels within 3 s | that file: 91 findings become 3 |
| CW-013: a DCOM server activated in a remote caller's network logon counts by itself | the MMC20 activation file: `mmc.exe -Embedding` in a logon from `10.23.123.11`, no command in the capture | lateral-movement folder: +1 file |

Written from the first corpus only, before the blind results were read: CW-013's main logic
(children of activated COM servers, mshta's LethalHTA activation), CW-014 (Startup folders
written over SMB or RDP), CW-015 (programs run from `\\tsclient`), `winrs` for CW-007 and
the logon-session source for CW-006/CW-007. This corpus has no Startup-folder drop, no
`\\tsclient` run and no `winrs` recording, and its one target-side DCOM file has no child
process, so those rules did not fire here, and none of them fired by mistake on 293
recordings of other attacks. The logon-session source did fire: on the wmiexec step it names
`10.23.123.11` for the WMI children, which moves that step onto the attacker's edge in the
story and changes no count. The source side of a DCOM call (a PowerShell script block
creating `MMC20.Application` on another host, the folder's second DCOM file) is not
detected.

An adversarial review of the new code then fixed how the new rules pick their sources
(connection direction, process IDs on 4688, RDP sessions, LogonIds reused across boots,
time-bounded host addresses) and a case where a remote PsExec next to a local one could be
called local. None of those changes moved the numbers on either corpus.

**After the changes** crabwalk flags 5 files of the lateral-movement folder at medium+, 4 of
them with a lateral alert (one through the CW-013 change this corpus prompted), and 54 of the
293 files, 17 with a lateral alert, with 69 alerts in all (180 blind). In the attack steps 6
files carry a lateral alert, since the local PsExec run no longer does. The engines still
lead on the lateral-movement folder.

**Known limitation it showed.** When two rules credit one service install to different
accounts, merging keeps both findings, since a merge never drops an actor, and the story tells
the install twice in one line. Here CW-012's pipe activity holds opens by two accounts from
`10.23.123.11` (`hack1` on a random-named pipe, `admmhorvath` on `svcctl`) and it names
`hack1`, while CW-001 names `admmhorvath` from the 4624 that preceded the install.

## What this does not show

- **Detection quality in the wild.** These are lab recordings, one technique each, so there
  are no false positives to count. The rule engines' alerts on these files are mostly true;
  their cost is volume.
- **Lateral movement as a whole.** The two folders hold 47 and 18 recordings by two authors,
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
