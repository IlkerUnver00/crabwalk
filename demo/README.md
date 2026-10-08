# Demo data

Nine small Windows event logs, so crabwalk produces real findings right after a
clone, with no download and no lab:

```bash
pip install -e .
crabwalk hunt demo/evtx --report report.html --graph attack-paths.html
```

```text
files      : 9
records    : 129  (kept: 123, unparsable: 0)
sessions   : 13 | edges: 12
findings   : 16  (critical 4, high 8, medium 4)
```

The same output is published as a live report on the project's GitHub Pages
site, rebuilt from this folder on every push.

## Where the files come from — and their licence

The `.evtx` files in [`evtx/`](evtx) are unmodified copies from
[sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
(commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`), a public corpus of attack
recordings by Samir Bousseaden. **They are licensed under the GNU GPL v3**; the
full text is in [`LICENSE.GPL`](LICENSE.GPL). This licence covers only the data
files in this folder. crabwalk's source code is MIT (see the repository root
[`LICENSE`](../LICENSE)) and does not depend on these files.

## What each file shows

| File | Host | What crabwalk finds |
|---|---|---|
| `LM_renamed_psexecsvc_5145.evtx` | IEWIN7 | A PsExec run with the service renamed to `blabla`, seen only in the target's 5145 share-access log. CW-012 (critical) recovers the **source machine, NLLT108334 at 10.0.2.16**, from the stdio pipe names. CW-005 flags the binary written to ADMIN$. |
| `LM_REMCOM_5145_TargetHost.evtx` | PC01 | RemCom (the engine of impacket's psexec): `RemComSvc.exe` copied to ADMIN$, then remote service control over `svcctl`. CW-012 critical, CW-005. |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | IEWIN7 | Metasploit psexec on a Sysmon-only host: a remote `\ntsvcs` pipe connection, then a service whose ImagePath is a `%COMSPEC% ... powershell -nop -w hidden` command line. CW-012 critical, T1543.003. |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | WIN-77LTAPHIQ1R | atexec-style remote task: `atsvc` pipe access from 10.0.2.17, then a randomly named task. CW-012, T1053.005. |
| `LM_WMIC_4648_rpcss.evtx` | PC01 | The *source* side of a WMI hop: 4648 explicit credentials towards WIN-77LTAPHIQ1R. |
| `LM_WMI_4624_4688_TargetHost.evtx` | WIN-77LTAPHIQ1R | The *target* side of WMI movement: network logons from 10.0.2.17 (PC01). The attack graph joins it with the 4648 above into one PC01 → WIN-77LTAPHIQ1R edge. |
| `LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx` | PC01 | `sekurlsa::pth`: a logon type 9 through `seclogo`. CW-003. |
| `CA_DCSync_4662.evtx` | DC1 | DCSync: directory replication rights used by a non-DC account. CW-011 critical. |
| `DE_renamed_psexec_service_sysmon_17_18.evtx` | MSEDGEWIN10 | Contrast case: a renamed PsExec whose client ran **on the same host**. CW-012 reports it as local execution, not lateral movement. |

## Reading the result honestly

These are **separate recordings** from one public lab, chosen to exercise
crabwalk's rules; they are not one real intrusion. The attack graph connects
them wherever the evidence links names and addresses. For example,
`NLLT108334 → PC01` exists because 10.0.2.16 is named NLLT108334 in one
recording and appears as the RemCom client in another. That is correct
correlation for a single investigation. Across unrelated captures, read it as
"the same lab address" rather than "the same attacker". The log-clearing
findings (CW-009) are part of how the original samples were recorded.

For the full corpus (278 files) and the ground-truth tests built on it, see
[Validation](../README.md#validation) in the main README.
