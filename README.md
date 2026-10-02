# WindowsBaselineSnapshot

Complete finding-list comparison against supplied Windows observations. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"baseline":"machine","observations":{"1000":{"state":"measured","method":"WindowsOptionalFeature","value":"Disabled"}}}`. `baseline` selects the complete frozen machine (418 rows) or user (56 rows) finding list, both bundled unchanged under the upstream MIT notice. Every selected row is reported; absent, unavailable, not_configured and method-mismatched records are OPEN. Measured values must be bounded strings or 64-bit integers. Operators cover equality, inequality, numeric boundaries, empty-or-equal and exact token membership; semicolon/comma tokens compare without order and with case folding. This avoids treating `NotDisabled` as `Disabled`. No fallback default is fabricated. Upstream PowerShell collectors, backup/GPO/hardening actions, scoring and substring comparator equivalence are outside this complete new scope. Source method labels and measured state are supplied claims, not authenticated Windows measurements. `good.json` is explicitly synthetic: recommendations copied as measurements only to exercise all policy rows.

## Use and output

Install `artifacts/*.whl` and run `windows-baseline-snapshot examples/good.json`, or `python -m windows_baseline_snapshot examples/good.json`. JSON findings have PASS/FAIL/OPEN, evidence, explanation and counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Incomplete/unsupported evidence cannot produce exit 0. Input: regular non-symlink unchanged file, 2 MiB maximum, 32 JSON layers, 100000 nodes, no duplicate keys/nonfinite values; findings cap 20000. Each project is independently packaged with no external runtime dependency.

## Verification and limits

Read `ORIGIN.md`, `NOTICE` where present, `tests/`, `examples/expectations.json`, `VALIDATION.md` and exact `artifacts/validation.json`. Tests use public frozen policy data or synthetic fixtures only. Local parser/policy/wheel/CLI results are separate from real Linux/Windows execution, effective security, upstream equivalence and CVP eligibility/approval, which remain OPEN. No live host collection, code execution, configuration change or network action occurs.
