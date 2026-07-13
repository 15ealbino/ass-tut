# Assembly Cost Analysis

> Feature branch: `feat/asm-cost-analysis`

## What it teaches

**Mission pillar 2 — teach engineers to spot bad/inefficient assembly and the
Python/C behind it.**

Every Python line compiles to some number of x86 instructions, and a few of
those instructions are far more expensive than the shift/add/move staples.
This feature makes that cost *visible per Python line*, so a learner can see —
concretely, on their own code — that:

- `a * b` becomes an `imul` (multiply),
- `a // b` becomes an `idiv` (integer division — tens of cycles),
- calling a helper is `call` overhead,
- …and, as a bonus lesson, that `x // 2` does **not** become an `idiv` at all —
  the compiler strength-reduces division by a power of two into a shift, so the
  `div` flag correctly does **not** appear. The flags reflect the *real emitted
  assembly*, not a guess from the Python source.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - A `COST:: N INSTR` chip shows the total number of x86 instructions
     attributable to your Python lines.
   - Each Python-line chip shows `·N` — the instruction count for that line.
   - Expensive lines get a red marker: `×` (multiply), `÷` (division),
     `⤳` (function call). Hover any chip for the full breakdown.
3. Compare rewrites. Change `x * 8` to `x << 3`, or `x // 2` to `x >> 1`, and
   watch the `×` / `÷` markers disappear and the instruction count drop.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives
(see `backend/app/compile.py::_parse_asm_line_map`). The cost feature adds a
pure post-processing pass on top of that mapping — no extra compilation:

```
compile_python()
  └─ _parse_asm_line_map()   # existing: c_line → [asm_line], filtered asm text
  └─ build_line_map()        # existing: py_line → {c_lines, asm_lines, color}
  └─ analyze_cost()          # NEW: annotate + summarize
```

`analyze_cost(line_map, asm_lines)` (in `backend/app/compile.py`):

- For each `line_map` entry, `asm_count = len(asm_lines)` for that Python line.
- For each mapped assembly line, it takes the first whitespace-separated token
  (the mnemonic), lowercases it, and classifies it via `_classify_mnemonic`.
  Classification is **prefix-based**, so one table entry covers every
  size-suffixed variant: `idiv`/`idivl`/`divl`/`divsd` → `div`,
  `imul`/`imull`/`mull`/`mulsd` → `mul`, `call`/`calll` → `call`.
- Flags per line are de-duplicated and ordered `div → mul → call`.
- A summary `{ total_instructions, hotspots }` is returned, where `hotspots`
  is the list of instruction-producing Python lines sorted by count descending
  (ties broken by line number for determinism).

The per-line `asm_count`/`flags` are attached to each `line_map` entry, and
`cost_summary` is added to the `/compile` response. Both are typed in
`backend/app/schemas.py` (`LineMapping.asm_count`, `LineMapping.flags`,
`CostSummary`, `Hotspot`) and mirrored in `frontend/src/api.ts`.

### A note on the total

`total_instructions` counts only instructions that GCC attributed to a source
line via a `.loc` directive — i.e. instructions reachable through `line_map`.
Function prologue/epilogue and some compiler-inserted setup carry no `.loc` and
are therefore excluded. Read the number as **"instructions attributable to your
Python lines,"** not the full length of the assembly listing. Because each
assembly line maps to exactly one C line and each C line to exactly one Python
line, there is no double-counting.

### Scope

- **In scope:** the `transpile` (AST → C → gcc) pipeline. Instruction counts and
  the three expensive-op flags (`div`, `mul`, `call`).
- **Out of scope:** the `pyghidra` pipeline (returns `cost_summary: null` and an
  empty `line_map` — it does not compute per-line cost); cycle-accurate latency
  modeling; per-instruction annotations inside the assembly pane; SSE/float
  cost categories beyond the prefix-shared `div`/`mul` flags.

## How to run its tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=test-secret-key pytest tests/test_cost_analysis.py -q
```

The test file has two layers:

- **Unit tests** (`_classify_mnemonic`, `analyze_cost`) — pure, no toolchain
  required. They cover mnemonic classification, per-line counts, flag ordering,
  the out-of-range-index guard, and the empty-input case.
- **End-to-end tests** — POST real Python to `/compile` and assert the cost
  signal reaches the response (multiply flagged, division flagged, a bare
  assignment left un-flagged, hotspots sorted descending). These are guarded by
  a `gcc -m32` availability check and **skip automatically** where 32-bit
  multilib is not installed, so the suite stays green in a toolchain-less
  environment.

Run the full backend suite the same way:

```bash
SECRET_KEY=test-secret-key pytest -q
```
