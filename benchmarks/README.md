# AutoPatch AI seed benchmark

> ⚠️ **Every file under `samples/` is intentionally vulnerable.**
> These files are test fixtures. Do not import, execute, deploy or copy them.
> All credentials in them are fake placeholders (`fake-benchmark-...`).

## What this is (and isn't)

A **small, hand-written seed set** of 9 Python snippets (3 per category) used to
develop and test AutoPatch AI's agents. It is **not** a comprehensive,
representative or real-world vulnerability dataset, and results on it should not
be presented as general performance. More samples (including safe "negative"
samples for measuring false positives) will be added for the evaluation in M7.

## Layout

```
benchmarks/
├─ README.md
├─ manifest.json                     # machine-readable index (validated by tests)
└─ samples/
   ├─ sql_injection/sqli_00N/app.py
   ├─ hardcoded_credentials/creds_00N/app.py
   └─ insecure_deserialization/deser_00N/app.py
```

Each sample has its own folder so reference fixes and per-sample tests can be
added next to it in later milestones.

## Manifest fields

| Field | Meaning |
|---|---|
| `sample_id` | Unique ID, e.g. `sqli-001` |
| `category` | `sql_injection`, `hardcoded_credentials` or `insecure_deserialization` |
| `description` | What the vulnerable code does |
| `vulnerable_file` | Path relative to `benchmarks/`, must sit under `samples/<category>/` |
| `expected_vulnerability` | Vulnerability type the scanner should report (must equal `category`) |
| `expected_cwe` | CWE ID for the weakness (must belong to the category) |
| `expected_rule_ids` | Bandit test IDs we expect to fire |
| `expected_lines` | 1-based line(s) where we expect the finding |

The schema is defined in `autopatch/models/benchmark.py`, and
`autopatch/benchmark.py` loads and checks it.

## Samples

| ID | Category | Pattern | Expected rule |
|---|---|---|---|
| sqli-001 | SQL injection | f-string `SELECT` | B608 |
| sqli-002 | SQL injection | `%`-formatted `DELETE` | B608 |
| sqli-003 | SQL injection | `str.format` with dynamic `ORDER BY` | B608 |
| creds-001 | Hardcoded credentials | password in module constant | B105 |
| creds-002 | Hardcoded credentials | token as keyword argument | B106 |
| creds-003 | Hardcoded credentials | password as default argument | B107 |
| deser-001 | Insecure deserialization | `pickle.loads` on cookie data | B301 |
| deser-002 | Insecure deserialization | `yaml.load` with `yaml.Loader` | B506 |
| deser-003 | Insecure deserialization | `marshal.loads` on file data | B302 |

## Notes

- **Expectations confirmed in M2 (Bandit 1.9.4).** All 9 samples were detected
  with the expected rule ID at the expected line, so no manifest changes were
  needed.
  - Bandit reports B107 (creds-003) with the line range 6–7 because it covers the
    function definition. The finding starts at the expected line 6.
  - Bandit rates B608 confidence LOW for the f-string (sqli-001) and
    `str.format` (sqli-003) samples, and MEDIUM for the `%` sample (sqli-002).
- Bandit also reports B403 (`import pickle`) at deser-001 line 6. AutoPatch lists
  it as a *related* finding, separate from the expected findings.
- **How samples are checked:** tests only read the files as text and parse them
  with `ast.parse`, which builds a syntax tree without running anything. Each
  file contains only imports, constants and class/function definitions. No
  vulnerable call runs at import time.
- `benchmarks/` sits outside the `tests/` folder pytest collects from and is not
  included in the built package.
