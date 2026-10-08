# crabwalk — dev notes

EVTX lateral movement hunter (portfolio project for SOC/DFIR job applications).
Conversation with the user is in Turkish; code, comments and docs stay in English.

- Python >= 3.10, src layout, hatchling build. Runtime dep: `evtx` (+ `tomli` on 3.10
  only). Dev: pytest. Commits: no "Co-Authored-By: Claude" trailer in this repo.
- Venv: `.venv\Scripts\python.exe`; tests: `.venv\Scripts\python.exe -m pytest tests -q`
- CLI: `crabwalk parse <paths> [--all | --event-id N | --channel X] [--out f.jsonl]`
       `crabwalk sessions <paths> [--include-machine] [--out f.json]`
       `crabwalk hunt <paths> [--out findings.json] [--report r.html] [--layer nav.json]
                             [--graph g.html|g.dot|g.json]`
- report.py = self-contained HTML (inline CSS + Python-generated SVG attack graph and
  swimlane timeline, theme-aware, no JS). navigator.py = ATT&CK layer JSON.
  style.py = shared CSS + severity palette (status palette, fixed, never themed).
- hosts.py = host identity (clean_ip, short_host, HostResolver: IP<->name collapsing).
  Never split an IP on '.' to get a "short name" — use short_host(), it returns None for IPs.
- graph.py = attack-path graph: one node per machine (HostResolver key), edges from
  session movement + findings carrying src_ip/src_host. Layout = longest path on a DAG
  (cycle-closing edges skipped in time order). Exports DOT/JSON/SVG/standalone HTML.
- Finding.src_ip/src_host: fill them whenever the evidence names the source; that is
  what turns a finding into a graph edge.
- HuntContext.service_installs merges 7045 + 4697 + Sysmon 13 (Services\*\ImagePath);
  use it instead of reading 7045 directly so rules work on Sysmon-only exports.
- catalog.CONTENT_FILTERS narrows high-volume IDs (Sysmon 13) at parse time; parser
  calls catalog.keep_event().
- Parse robustness: parser._read_records() never raises for a bad file or record;
  file-level problems go to ParseStats.file_problems (never capped), record-level to
  errors (capped at 20). CLI exits 1 only if files errored AND zero records were read.
- Named-pipe telemetry: Sysmon 18 with Image "System" = connection arrived over SMB
  (remote). Security 5145 on IPC$ logs the pipe in RelativeTargetName + client IpAddress.
  PsExec stdio pipes "<svc>-<SOURCEHOST>-<pid>-stdin" name the machine PsExec ran on.
- Rules live in `src/crabwalk/rules/` (base.py = Rule/Finding/HuntContext; one module
  per theme). New rule: subclass Rule, add to ALL_RULES in rules/__init__.py, test it.
- config.py = TOML tuning layer (`hunt --config`, `crabwalk config [FILE|--example]`).
  A rule exposes a knob by giving it a class-level default and listing its name in
  `tunables`; the default's type (bool/timedelta/int/tuple) decides parsing, and
  `crabwalk config --example` picks it up automatically (a test enforces it). Read
  tunables from `self`, never from module constants. Allowlist suppresses findings
  AFTER the rules run; suppressed ones must stay visible (CLI count, JSON, report).
  `fields` = one table (`[allow.fields]`) or several (`[[allow.fields]]`); EVERY
  evidence event must fully match one table (carry all its fields, all regexes hold).
  That fails closed on typos/foreign fields. Each table must name one of
  config.IDENTIFYING_FIELDS (an allowlist: ServiceName, ImagePath, RelativeTargetName,
  PipeName, TaskContent, CommandLine, ScriptBlockText...); anything else (who/where,
  Image, per-type constants like AccountName/ObjectType) may only narrow. Empty tables
  and any-value regexes (probed against _PROBES) are refused at load. Near misses warn
  (screen() gets ctx.events for the typo check). A rule that adds an event type to its
  `evidence` changes what entries must describe — if that type needs a new identifying
  field, add it to IDENTIFYING_FIELDS (CW-001 keeps the install only, its logon is
  users/sources; CW-002's hop records are who/where only).
- Anonymous logons: `hosts.is_anonymous(name, sid)` — the SID (S-1-5-7) decides; the
  name is localized, so it is only the fallback for records without a SID.
- Docs: docs/DETECTIONS.md = per-rule reference (pins a commit and test counts) —
  update it with any change to a rule's logic, tunables, evidence or validation.
  docs/writeups/ (case write-ups on demo/evtx data), docs/COMPARISON.md (sourced claims
  about other tools), sigma/ (pySigma-validated, not loaded by crabwalk). demo/ = nine
  GPL-3.0 corpus files; tests/test_demo.py pins their results and always runs in CI.
- Machine accounts: always `hosts.is_machine_account()` (handles `DOM\PC$`,
  `PC$@REALM`); never `endswith("$")` inline.
- Test data: `samples\EVTX-ATTACK-SAMPLES` (sbousseaden repo, shallow clone, gitignored);
  integration check: `crabwalk sessions "samples\EVTX-ATTACK-SAMPLES\Lateral Movement"`
- tests/test_corpus.py = ground-truth harness (filename->technique), skips if corpus
  absent; resolve via CRABWALK_SAMPLES env or default samples\ path. Add a new detection
  rule => also add a corpus entry proving it fires on a known sample, and a
  NEGATIVE_TRUTH entry for look-alike attacker activity it must not mislabel.
- Visual check of HTML output: render with Edge headless
  (`msedge --headless=new --screenshot=out.png --window-size=1300,1212 file:///...`,
  URL-encode the ü in Masaüstü as %C3%BC) and look at the PNG; docs/report-screenshot.png
  is the README hero.
- Parser reality (learned the hard way): pyevtx-rs nests XML attributes under
  `#attributes` (Provider Name, TimeCreated SystemTime, Security UserID) — NOT `@name`.
  Record-level `timestamp` is often FILETIME-null (1601); event_timestamp() prefers
  System/TimeCreated/@SystemTime. dedup_events() collapses same-record copies across
  overlapping exports (keyed on computer+channel+record_id+ts).
- Design rules: unparsable records are counted, never fatal; minimal dependencies
  (offline DFIR boxes); all timestamps UTC.
- `samples/` is gitignored — local EVTX test data lives there.
- Roadmap lives in README.md — keep the checkboxes current as steps land.
