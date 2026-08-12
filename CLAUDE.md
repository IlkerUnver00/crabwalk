# crabwalk — dev notes

EVTX lateral movement hunter (portfolio project for SOC/DFIR job applications).
Conversation with the user is in Turkish; code, comments and docs stay in English.

- Python >= 3.10, src layout, hatchling build. Runtime dep: `evtx` only. Dev: pytest.
- Venv: `.venv\Scripts\python.exe`; tests: `.venv\Scripts\python.exe -m pytest tests -q`
- CLI: `crabwalk parse <paths> [--all | --event-id N | --channel X] [--out f.jsonl]`
       `crabwalk sessions <paths> [--include-machine] [--out f.json]`
       `crabwalk hunt <paths> [--out findings.json] [--report r.html] [--layer nav.json]`
- report.py = self-contained HTML (inline CSS + Python-generated SVG swimlane timeline,
  severity uses the fixed status palette, theme-aware). navigator.py = ATT&CK layer JSON.
- Rules live in `src/crabwalk/rules/` (base.py = Rule/Finding/HuntContext; one module
  per theme). New rule: subclass Rule, add to ALL_RULES in rules/__init__.py, test it.
- Test data: `samples\EVTX-ATTACK-SAMPLES` (sbousseaden repo, shallow clone, gitignored);
  integration check: `crabwalk sessions "samples\EVTX-ATTACK-SAMPLES\Lateral Movement"`
- tests/test_corpus.py = ground-truth harness (filename->technique), skips if corpus
  absent; resolve via CRABWALK_SAMPLES env or default samples\ path. Add a new detection
  rule => also add a corpus entry proving it fires on a known sample.
- Parser reality (learned the hard way): pyevtx-rs nests XML attributes under
  `#attributes` (Provider Name, TimeCreated SystemTime, Security UserID) — NOT `@name`.
  Record-level `timestamp` is often FILETIME-null (1601); event_timestamp() prefers
  System/TimeCreated/@SystemTime. dedup_events() collapses same-record copies across
  overlapping exports (keyed on computer+channel+record_id+ts).
- Design rules: unparsable records are counted, never fatal; minimal dependencies
  (offline DFIR boxes); all timestamps UTC.
- `samples/` is gitignored — local EVTX test data lives there.
- Roadmap lives in README.md — keep the checkboxes current as steps land.
