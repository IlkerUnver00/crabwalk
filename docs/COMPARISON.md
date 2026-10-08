# How crabwalk compares

This page places crabwalk among open-source tools for analysing Windows event logs,
plus Timeline Explorer, a free viewer whose licence is not verified.
It compares documented capabilities only. No head-to-head benchmark was run, and
"not verified" means the tool's own docs or source did not settle the question.
Facts about other tools were checked against their READMEs, docs and source on
2026-10-08 and are footnoted. Facts about crabwalk refer to this repository at
version 0.1.0.

## The short version

Chainsaw, Hayabusa and Zircolite are **rule engines**. They run thousands of Sigma
(or native) rules over events and are the right first pass over unknown evidence.
DeepBlueCLI and APT-Hunter ship **built-in detections**. LogonTracer **graphs
logons** in a Neo4j database. EvtxECmd and Timeline Explorer **normalise and
display** events and do not detect anything.

crabwalk answers one question: *where did the attacker log on, and where did they
go next?* It has 12 hand-written rules, reads Windows EVTX only, and is not a Sigma
engine. It is not the only tool that graphs logons: LogonTracer links accounts to
hosts, and Zircolite correlates across files. What crabwalk adds is a
**host-to-host graph without a database server**. It keeps logon sessions per host
and builds movement edges between hosts. The edges come from logon events (4624,
4648, RDP) and also from detections that are not logons: PsExec pipe names in 5145
and executables dropped on ADMIN$. It works out that an IP address and a hostname
are the same machine, draws the result as an attack-path graph, and tells it as a
dated story (one line per step, as whom, from where, with its own doubts stated).
Use it
**alongside** a Sigma engine, not instead of one.

## Per-tool notes

**Chainsaw** (Rust, GPL-3.0[^cs-lic]). Hunts with Sigma rules (loaded from a
separate SigmaHQ clone through a field-mapping file) and with Chainsaw's own YAML
rules[^cs-readme]. The repo holds 78 EVTX and 53 MFT rule files[^cs-rules]. Its
built-in `lateral_movement` rules flag individual logons by type[^cs-rules]. The
only Sigma aggregation it parses is `count([field]) [by field]`, and `timeframe` is
ignored[^cs-sigma]. Searching the repo for `correlation` returned only test
fixtures, so Sigma v2 correlation support was not found[^cs-search]. It also covers
MFT, registry hives, SRUM and Shimcache/Amcache, which crabwalk does not.

**Hayabusa** (Rust, AGPL-3.0; rules under DRL 1.1[^hb-readme]). A timeline
generator with "4,000+ curated detection rules"[^hb-docs]. Its docs give worked
examples of all four Sigma v2 correlation types: event count, value count, temporal
proximity and ordered temporal proximity[^hb-corr]. `logon-summary`
counts successful and failed logons from 4624, RDS-LSM 21, RDS-GTW 302 and
4625[^hb-analysis]. It also has a live mode and an HTML results summary[^hb-timeline].

**Zircolite** (Python, LGPL-3.0[^zc]). Converts Sigma to SQL with pySigma's SQLite
backend. Its default `rules_windows_merged.json` holds 4,515 rules[^zc-rules]. It
reads the widest range of log formats here and supports "counts, statistics, temporal
sequences, absence conditions and chained rules", with a unified mode for
cross-file correlation[^zc].

**LogonTracer** (Python 3.9+ with a Neo4j 5.x server; BSD-3-Clause[^lt-lic]). From
JPCERT/CC. Imports EVTX, XML or Elasticsearch data. It links accounts to the host
names or IP addresses found in logon-related events (4624, 4625, 4672, 4768, 4769,
4776 and others) and shows them as a graph in a web UI[^lt]. It ranks hosts and
accounts with PageRank, a hidden Markov model and ChangeFinder, has a chronological
view, and can scan with bundled SigmaHQ rules. Version 2 adds optional analysis
through OpenAI GPT models, which needs an API key[^lt]. Its documented graph is
account-to-host and built from logon events; crabwalk's is host-to-host and also
takes edges from non-logon detections.

**DeepBlueCLI** (PowerShell, plus a Python port; GPL-3.0[^dbc][^gh]). Runs fixed
checks such as password spraying, obfuscated command lines and suspicious service
creation[^dbc]. Its last push was 2023-10-14[^gh].

**APT-Hunter** (Python, GPL-3.0[^apt]). Has built-in detections plus Sigma rules
converted to JSON. It writes Excel/CSV timelines, a logon report and a web
dashboard. Its optional LLM triage "links what it finds into attack chains"[^apt].
That chaining depends on an LLM (with a fixed pivot/correlate fallback when the
model lacks tool calling); no deterministic host-to-host path is documented[^apt].

**EvtxECmd / Timeline Explorer** (C#, .NET 4.7.2 and .NET 9[^ecmd-proj]). EvtxECmd
turns EVTX (including Volume Shadow Copies) into CSV/JSON/XML. Its 468 "Maps"
normalise EventData[^ecmd]. It has no detections. Timeline Explorer is a
.NET 9 GUI for viewing that output[^ez]. EvtxECmd's repo is MIT[^gh]. No public
source repo for Timeline Explorer was found, so its licence is not verified.

**Sigma correlation rules** (specification v2.1.0[^sigma-corr]). Defines
`event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum`,
`value_avg` and `value_percentile` over a `timespan`, grouped by fields. Field
**aliases** let one rule's source address join another rule's destination address,
so a single two-event hop between hosts *can* be expressed[^sigma-corr]. Whether
Hayabusa implements field aliases is not verified.

## Matrix: platform

| Tool | Runtime | Input | Output | Licence |
|---|---|---|---|---|
| crabwalk | Python ≥ 3.10; deps `evtx` (+ `tomli` on 3.10) | `.evtx` files and directories | console; JSONL events; JSON sessions/findings; HTML report; ATT&CK Navigator layer; graph as HTML/DOT/JSON; attack story (text/Markdown/HTML) | MIT |
| Chainsaw | Rust[^cs-readme] | EVTX, JSON, JSONL, XML; MFT, hives, ESE, SRUM, Shimcache/Amcache[^cs-readme][^cs-file] | table, CSV, JSON, log[^cs-readme]; JSONL[^cs-main] | GPL-3.0[^cs-lic] |
| Hayabusa | Rust[^hb-readme] | EVTX, JSON/JSONL (`-J`), live (`-l`)[^hb-timeline] | CSV/JSON/JSONL timeline, HTML summary[^hb-timeline] | AGPL-3.0[^hb-readme] |
| Zircolite | Python 3.10+, standalone binaries[^zc] | EVTX, XML, JSONL, CSV, JSON array, Auditd, Sysmon for Linux, archives[^zc] | JSON, CSV, templates (Splunk, Elastic, Timesketch, SARIF, Navigator…)[^zc] | LGPL-3.0[^zc] |
| LogonTracer | Python 3.9+, Neo4j 5.x[^lt] | EVTX, XML, Elasticsearch[^lt] | web UI: graph, timeline, Sigma results table[^lt] | BSD-3-Clause[^lt-lic] |
| DeepBlueCLI | PowerShell; Python port[^dbc] | live logs, EVTX[^dbc] | PowerShell objects (CSV, JSON, HTML via cmdlets)[^dbc] | GPL-3.0[^gh] |
| APT-Hunter | Python 3.8+, binaries[^apt] | EVTX file/folder; Office 365 audit logs[^apt] | Excel, CSV (Timesketch), reports, web dashboard[^apt] | GPL-3.0[^apt] |
| EvtxECmd / TLE | .NET 4.7.2 / .NET 9[^ecmd-proj][^ez] | EVTX files, dirs, VSS[^ecmd] | CSV, JSON, XML[^ecmd] | MIT (EvtxECmd)[^gh]; TLE not verified |

## Matrix: detection and correlation

| Tool | Rules | Timeline | Cross-event / cross-host correlation | Offline |
|---|---|---|---|---|
| crabwalk | 12 Python rules, ATT&CK-tagged; tunable via TOML | time-sorted JSONL; per-host swimlane in report | LogonId sessions per host (4672 backfill); 4624/4648/RDP edges; IP↔name host resolution (not time-scoped); two-hop RDP chains (A→B→C within a tunable 6 h window); PsExec source host from pipe names; one event told once across rules; attack-path graph and dated story | no network code |
| Chainsaw | Sigma (external) + 131 Chainsaw rule files[^cs-rules] | Shimcache/Amcache execution timeline[^cs-readme] | Sigma `count() by` only, no timeframe[^cs-sigma]; v2 correlation not found[^cs-search] | all-in-one release with rules[^cs-readme] |
| Hayabusa | 4,000+ curated[^hb-docs] | yes, core purpose[^hb-readme] | Sigma v2: 4 types, `group-by`[^hb-corr]; logon counts[^hb-analysis]; sessions/host graph not found in docs | yes; `update-rules` needs network[^hb-readme] |
| Zircolite | Sigma → SQLite; 4,515 in default set[^zc-rules] | Timesketch template, GUI[^zc] | counts, temporal sequences, chained rules, cross-file[^zc]; host graph not documented | yes; standalone binaries; `-U` rule update needs network[^zc] |
| LogonTracer | bundled SigmaHQ (optional scan); PageRank, HMM, ChangeFinder[^lt] | chronological view[^lt] | account↔host logon graph[^lt]; host-to-host edges not documented | needs a Neo4j server; optional AI analysis uses OpenAI[^lt] |
| DeepBlueCLI | fixed checks[^dbc] | not verified | threshold checks within a log[^dbc]; cross-host not documented | not verified |
| APT-Hunter | built-in + Sigma JSON[^apt]; count not verified | yes[^apt] | logon report; optional LLM "attack chains"[^apt] | not verified |
| EvtxECmd / TLE | none; 468 Maps[^ecmd] | CSV for TLE[^ez] | none | maps are local; `--sync` (off by default) downloads them[^ecmd] |

## What crabwalk's correlation does, concretely

One sample from the
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus,
a renamed PsExec seen only through the target's share-access log (5145):

```text
> crabwalk hunt "samples\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_renamed_psexecsvc_5145.evtx" --graph psexec.json
files      : 1
records    : 22  (kept: 22, unparsable: 0)
sessions   : 0 | edges: 0
findings   : 1  (critical 1)

[CRITICAL] 2019-01-19 13:00:10Z  CW-012  Remote execution over named pipes
    host: IEWIN7   user: IEWIN7\IEUser   ATT&CK: T1021.002, T1569.002, T1570
...
```

`psexec.json` holds 2 host nodes and 1 edge, `NLLT108334 → IEWIN7`, carrying the
CW-012 finding (CW-005 matches the same `ADMIN$` record and is listed under it, not
as a second finding). The file has no logon events, so there are no sessions;
the source host comes from the pipe names. CW-012 recovers the attacker's machine
`NLLT108334` from `\blabla-NLLT108334-37048-stdin` and ties it to client address
10.0.2.16. A per-event rule can match that pipe name, but it does not turn the
hostname inside it into an edge between two machines.

The session table and the graph cover the whole evidence set. The rules that link
events still use tunable time windows, similar to a Sigma `timespan`: 10 min for
CW-001 (logon → service install), 6 h for CW-002 (RDP chain), 2 to 5 min for
CW-012. A 4648 on the source and a 4624 on the target land on the same
source→target edge; they are aggregated, not matched one-to-one. `WIN-1`,
`WIN-1.corp.local` and `10.0.2.17` become one node wherever a 4624 pairs the
address with a workstation name.

### The whole corpus: a stress test, not one incident

The corpus is a set of unrelated lab captures from different domains and dates.
Running over all of it checks robustness; the resulting graph is not one intrusion:

```text
> crabwalk hunt samples\EVTX-ATTACK-SAMPLES --graph g.json
files      : 278
records    : 37364  (kept: 3011, unparsable: 0)
sessions   : 79 | edges: 36
findings   : 72  (critical 4, high 51, medium 17)
...
```

The 36 edges are session-layer movement records (logon, 4648, RDP), machine
accounts included. The graph drops machine accounts and records with no remote
source, adds findings that carry a source address, and merges everything per host
pair: `g.json` holds 16 host nodes and 9 directed edges. Its connected components
are not proven attack paths. The edge `NLLT108334 → PC01` (2019-02-16) comes from
`LM_REMCOM_5145_TargetHost.evtx`, which records only client 10.0.2.16; run alone,
that file gives `ip:10.0.2.16 → pc01`. The name was learned from the IEWIN7 capture
of 2019-01-19 above, where the same address appears with that name. That edge
connects the January capture to the February and March ones in a single component.
The attack story does not hide this: it names that step's source "10.0.2.16 (named
NLLT108334 elsewhere in the logs)" and opens the path with a caution that its steps
are weeks apart and joined only by names and addresses.

The limits come from the same design. Host resolution only works when the logs
pair an address with a name. Host resolution is not time-scoped: an address
learned anywhere in the evidence set is mapped to that name everywhere, so DHCP or
NAT address reuse, or unrelated evidence loaded together, can merge different
machines or create false edges. When one address was seen with several names, the
most frequent name wins. RDP chains need logon events from each hop. Coverage is
the 12 rules and nothing else.

## When to use which

- **Unknown evidence, first pass:** Hayabusa or Chainsaw. They have broad rule
  coverage, native Rust binaries. Zircolite if the logs are not
  EVTX or you need SIEM-shaped output.
- **Non-event-log artefacts** (MFT, SRUM, Shimcache): Chainsaw.
- **Account-centric logon analysis of Active Directory event logs in a GUI:**
  LogonTracer, if a Neo4j server is acceptable.
- **Reading events by hand:** EvtxECmd into Timeline Explorer.
- **Quick triage on one Windows box with a PowerShell script:** DeepBlueCLI,
  keeping in mind that it has not been updated since 2023.
- **"Which hosts did they move between, as whom, and in what order?":** crabwalk,
  on evidence from one incident. Then confirm each edge against the Sigma timeline
  from one of the tools above. crabwalk is younger and less battle-tested than any
  of them: version 0.1.0, validated mainly against one public corpus.

A Sigma engine finds suspicious events; crabwalk links lateral-movement events
into a path and tells it as a story. Run both and compare their output.

[^cs-readme]: Chainsaw README, <https://github.com/WithSecureOpenSource/chainsaw> (moved from WithSecureLabs/chainsaw).
[^cs-lic]: GitHub REST API `repos/WithSecureOpenSource/chainsaw`, `license.spdx_id` = GPL-3.0; licence file <https://github.com/WithSecureOpenSource/chainsaw/blob/master/LICENCE>.
[^cs-rules]: <https://github.com/WithSecureOpenSource/chainsaw/tree/master/rules>, files counted via the GitHub git-tree API: 78 under `rules/evtx`, 53 under `rules/mft`.
[^cs-sigma]: `prepare_condition` ("We only support count atm", optional `by` field) and the `timeframe` branch ("Ignore for now") in <https://github.com/WithSecureOpenSource/chainsaw/blob/master/src/rule/sigma.rs>.
[^cs-search]: `gh search code --repo WithSecureOpenSource/chainsaw correlation` matched only files under `tests/evtx/`.
[^cs-main]: `--jsonl` on the `dump`, `hunt` and `search` subcommands in <https://github.com/WithSecureOpenSource/chainsaw/blob/master/src/main.rs>; the README lists it only under `dump`.
[^cs-file]: `Kind::Jsonl` (extension `jsonl`) in <https://github.com/WithSecureOpenSource/chainsaw/blob/master/src/file/mod.rs>.
[^hb-readme]: Hayabusa README, <https://github.com/Yamato-Security/hayabusa>; `update-rules` in <https://github.com/Yamato-Security/hayabusa/blob/main/OLD-README.md>.
[^hb-docs]: <https://yamato-security.github.io/hayabusa/>.
[^hb-timeline]: <https://yamato-security.github.io/hayabusa/commands/dfir-timeline/> (`-J`, `-l`, `-H`).
[^hb-analysis]: <https://yamato-security.github.io/hayabusa/commands/analysis/> (`logon-summary`).
[^hb-corr]: <https://yamato-security.github.io/hayabusa/rules/correlations/>.
[^zc]: Zircolite README, <https://github.com/wagga40/Zircolite>.
[^zc-rules]: `len()` of the JSON list in <https://github.com/wagga40/Zircolite/blob/master/rules/rules_windows_merged.json>.
[^lt]: LogonTracer README, <https://github.com/JPCERTCC/LogonTracer> ("Concept", "What's New in Version 2.0", "Additional Analysis", "Requirements", "Usage").
[^lt-lic]: <https://github.com/JPCERTCC/LogonTracer/blob/master/LICENSE.txt> ("The 3-Clause BSD License"); the GitHub API reports `NOASSERTION` for this repo.
[^dbc]: DeepBlueCLI README, <https://github.com/sans-blue-team/DeepBlueCLI>.
[^apt]: APT-Hunter README, <https://github.com/ahmedkhlief/APT-Hunter> ("Agentic Triage").
[^ecmd]: EvtxECmd README and Maps, <https://github.com/EricZimmerman/evtx> (468 `.map` files under `evtx/Maps`).
[^ecmd-proj]: `<TargetFrameworks>net472;net9.0</TargetFrameworks>` in <https://github.com/EricZimmerman/evtx/blob/master/EvtxECmd/EvtxECmd.csproj>.
[^ez]: <https://ericzimmerman.github.io/> (GUI tools on .NET 9).
[^gh]: GitHub REST API `repos/{owner}/{repo}` (`license`, `pushed_at`) for sans-blue-team/DeepBlueCLI and EricZimmerman/evtx.
[^sigma-corr]: <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md>.
