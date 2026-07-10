# Assembly Cost Lens

Per-line **assembly-expansion metrics** for the Python → C → x86 pipeline.

## What it teaches

**Mission pillar 2 — spot bad / inefficient assembly and the code behind it.**

A single, innocent-looking line of Python can compile into many x86
instructions. The cost lens makes that expansion *visible*: every Python line
in the TRACE bar is badged with the number of assembly instructions it produced,
and lines that balloon past a threshold are flagged as **hotspots**. Learners
can immediately see *which* line is expensive, click it to highlight the exact
C and assembly it generated, and reason about *why* — a `%`/`//` that lowers to
`idiv`, a multi-argument `print` that sets up a `printf` call frame, a loop body
that repeats work, and so on.

## How a learner uses it

1. Write Python in the editor and compile (default `transpile` backend).
2. Look at the **TRACE::** bar along the bottom of the editor:
   - A summary chip shows `COST:: <N> INSTR` — total x86 instructions emitted —
     and, when present, `⚠ <k> HOT` — how many lines are hotspots.
   - Each per-line chip shows `×<n>` — the number of assembly instructions that
     Python line expanded into.
   - Hotspot lines (`×n` at or above the threshold) are prefixed with `⚠` and
     tinted red. Hover any chip for the exact count and hotspot status.
3. Click a hotspot chip to highlight its C and assembly lines in the other two
   panes and study what made it expensive.

The threshold is a fixed, explainable constant: **any Python line that compiles
to `HOTSPOT_THRESHOLD` (default 10) or more assembly instructions is a hotspot.**

## How it works technically

The metric is derived from the line map the pipeline already builds — no extra
compilation:

1. `transpiler.transpile()` records `py_lineno → [c_lineno]`.
2. `compile._parse_asm_line_map()` parses GCC `.loc` directives into
   `c_lineno → [asm_lineno]`.
3. `transpiler.build_line_map()` joins these into
   `py_lineno → { c_lines, asm_lines, color, c_count, asm_count }`. The two
   `*_count` fields are new: the length of the de-duplicated line lists.
4. `metrics.build_expansion_metrics(line_map)` (new, pure — no gcc, no I/O)
   summarizes the map:

   | field                    | meaning                                             |
   |--------------------------|-----------------------------------------------------|
   | `total_asm_instructions` | sum of `asm_count` over all mapped Python lines      |
   | `total_c_lines`          | sum of `c_count` over all mapped Python lines        |
   | `line_count`             | number of Python lines that mapped to any output     |
   | `mean_asm_per_line`      | `total_asm_instructions / line_count` (0.0 if none)  |
   | `max_asm_line`           | busiest Python line (ties → lowest lineno; None if 0)|
   | `hotspots`               | sorted Python lines with `asm_count >= threshold`    |
   | `hotspot_threshold`      | the threshold used (echoed for the UI)               |
   | `per_line`               | `py_lineno → { c_count, asm_count }`                 |

5. `compile.compile_python()` attaches the summary as `metrics` on the response.
   The `pyghidra` backend builds no line map, so its `metrics` is `null`.
6. The frontend (`api.ts` types, `Editor.tsx` TRACE bar) renders the badges and
   hotspot markers.

### Files

| File | Change |
|------|--------|
| `backend/app/metrics.py`     | **new** — `build_expansion_metrics`, `HOTSPOT_THRESHOLD` |
| `backend/app/transpiler.py`  | `build_line_map` adds `c_count` / `asm_count` per entry |
| `backend/app/compile.py`     | attaches `metrics` to the transpile response |
| `backend/app/schemas.py`     | `LineMapping.{c_count,asm_count}`, `LineMetric`, `ExpansionMetrics`, `CompileResponse.metrics` |
| `frontend/src/api.ts`        | `ExpansionMetrics` / `LineMetric` types; `metrics` field |
| `frontend/src/pages/Editor.tsx` | TRACE-bar summary chip + per-line `×n` badge and `⚠` hotspot marker |

## Scope

**In scope:** per-line C/asm counts, a response-level summary, hotspot flagging,
and the TRACE-bar UI for the `transpile` backend.

**Out of scope:** hotspot metrics for the `pyghidra` backend (returns `null`),
per-instruction categorization (memory / branch / arithmetic), and any
user-configurable threshold. These are natural follow-ups.

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=testsecret pytest tests/test_metrics.py -q
```

`tests/test_metrics.py` covers:

- **Pure metrics** (no gcc): empty map, count/mean math, `max_asm_line`
  tie-breaking and the all-zero case, inclusive hotspot threshold, sorted
  hotspots, and defensive handling of entries missing `asm_lines`.
- **`build_line_map`**: the new `c_count` / `asm_count` fields and their
  agreement with `build_expansion_metrics`.
- **End-to-end** (`@requires_gcc`, needs `gcc -m32` + 32-bit libc headers, e.g.
  `apt-get install gcc-multilib`): the `/compile` response carries a populated
  `metrics` block whose totals reconcile with `per_line`, `line_map` entries
  carry `asm_count`, a heavy-arithmetic / multi-arg-`print` program is flagged
  as a hotspot, and the `pyghidra` path yields `metrics: null`. E2E tests skip
  automatically when 32-bit compilation is unavailable.
