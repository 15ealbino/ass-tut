# Assembly Instruction Mix

> Feature branch: `feat/asm-instruction-mix`

## What it teaches

**Mission pillar 2 — teach engineers to spot bad/inefficient assembly and the
Python/C behind it.**

The existing [cost analysis](../asm-cost-analysis/README.md) answers *how much*:
the total instruction count per Python line, plus a red flag on the few
expensive mnemonics (`×` multiply, `÷` division, `⤳` call). The instruction mix
answers a different, complementary question — **what *kind* of work** does each
Python line's assembly actually do?

Every real x86 instruction a Python line maps to is sorted into exactly one of
six categories:

| Category  | Meaning                          | Example mnemonics                     |
|-----------|----------------------------------|---------------------------------------|
| `mem`     | data movement / memory traffic   | `movl`, `leal`, `movzbl`, `cltd`, x87 `fld`/`fstp` |
| `compute` | arithmetic + logic               | `addl`, `subl`, `imull`, `idivl`, `andl`, `sall`, `fmul` |
| `branch`  | control flow (jumps + the cmp/test/setcc that drive them) | `jmp`, `je`, `jle`, `cmpl`, `testl`, `sete` |
| `call`    | call / return overhead           | `call`, `ret`, `leave`                |
| `stack`   | explicit stack management        | `pushl`, `popl`, `enter`              |
| `other`   | anything unrecognised            | `nop`, …                              |

Why this is a distinct lesson from the raw count: at `gcc -O0` every variable is
spilled to the stack, so a single arithmetic step in Python explodes into a pile
of `mem` moves around one or two `compute` instructions. A line that reads as
`x = a + b` but compiles to *6 mem, 1 compute* is showing you, concretely, the
memory-traffic cost of unoptimised code — and it trains the eye to notice when
the **composition** looks wrong (all memory, no compute), not just when the
count is high. That composition-reading skill is the first diagnostic step
toward spotting inefficient assembly.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - The `COST:: N INSTR` chip (from the cost feature) shows the total
     instruction count.
   - A new `MIX:: mem N · compute N · branch N …` chip shows the whole
     program's instruction mix, in a stable category order. Categories with a
     zero count are omitted.
   - Hover any per-line chip: its tooltip now includes `mix: mem N · compute N …`
     alongside the instruction count and any expensive-op flags.
3. Experiment. Add an `if`/`for` and watch `branch` climb. Call a helper and
   watch `call` appear. Notice how even a trivial assignment is dominated by
   `mem` at `-O0` — then imagine what `-O2` register allocation would remove.

### Worked example

Compiling:

```python
x = 0
for i in range(5):
    if i > 2:
        x = x + i * i
```

produces (categories shown per Python line):

```
total_instructions: 11
category_totals: {'mem': 3, 'compute': 3, 'branch': 5}
  L1: count=1  mix={'mem': 1}                          # store 0
  L2: count=5  mix={'mem': 1, 'compute': 1, 'branch': 3}   # loop counter + compare/jumps
  L3: count=2  mix={'branch': 2}                       # cmp + conditional jump
  L4: count=3  mix={'mem': 1, 'compute': 2}  flags=['mul']  # load/store + add + imul
```

The `flags=['mul']` on L4 (from the cost feature) tells you *that* line has an
expensive multiply; the `mix` tells you the multiply sits amid a load/store and
an add — the full shape of the work.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost pass annotates each entry with `asm_count` / `flags`
(see `backend/app/compile.py::analyze_cost`). The instruction-mix feature is a
few extra lines inside that **same** pass — no additional compilation:

1. `classify_category(mnemonic)` (in `backend/app/compile.py`) maps a lowercased
   mnemonic to one of the six categories via an ordered prefix table
   (`_CATEGORY_PREFIXES`, first match wins). Prefix matching means one entry
   covers every size-suffixed variant — `"mov"` catches `movl`/`movzbl`/`movsbl`,
   `"j"` catches every conditional jump. Unlike the flag classifier, it is
   *total*: an unknown or empty mnemonic returns `"other"`, never `None`.
2. In `analyze_cost`, as each mapped instruction is already being inspected for
   cost flags, it is also classified and tallied into a per-line counter and a
   program-wide counter.
3. Each `line_map` entry gains `category_counts` (zero categories dropped, keys
   in canonical `mem → compute → branch → call → stack → other` order), and the
   returned `cost_summary` gains `category_totals` in the same shape.
4. These fields are declared on `LineMapping` and `CostSummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline — which
   computes no per-line mix — still validates), and mirrored in the frontend
   types in `frontend/src/api.ts`. `frontend/src/pages/Editor.tsx` renders the
   `MIX::` chip and the enriched tooltips.

**Invariant:** for real gcc output, a line's `category_counts` values sum to its
`asm_count`, and `category_totals` sums to `total_instructions` — every counted
instruction lands in exactly one bucket. (A defensively-skipped out-of-range asm
index is the only case where the sum can trail the count.)

## Scope

- **In scope:** classification of the instructions each Python line already maps
  to, plus per-line and program-wide mix in the API and a minimal editor
  read-out.
- **Out of scope:** any change to the transpiler or C/asm generation;
  cycle-accurate timing; reworking the existing `div`/`mul`/`call` flags (the mix
  is orthogonal and additive); the pyghidra pipeline; rich charts/visualisation.

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_instruction_mix.py
```

The test file has two layers:

- **Unit tests** for `classify_category` (every category, size-suffixed variants,
  and the total `"other"` fallback) and for `analyze_cost`'s mix annotations
  (the sum invariant, zero-category omission, canonical ordering, out-of-range
  defensiveness, and a regression check that the existing cost fields are
  untouched). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the mix reaches the API response (`compute` on a multiply, `call` on a
  function call, `branch` on a conditional, and the program-wide sum invariant).
  These are marked `needs_gcc` and **skip automatically** if `gcc` with `-m32`
  support (the 32-bit multilib) is unavailable, so the suite still passes in a
  toolchain-less environment.
