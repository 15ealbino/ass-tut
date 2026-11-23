# Immediate-Value Map

> Feature branch: `feat/immediate-value-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete and traceable**,
with a direct **pillar 2** edge (read the bound a guard hinges on straight off the
disassembly).

The [addressing-mode map](../addressing-modes/README.md) classifies each asm
operand by *how it forms its address*, and counts how many operands are
**immediates** (`$5`, `$100`). But a count is all it gives: "2 immediate operands"
never tells you *which* constants those are.

The immediate-value map answers the value-level question: **which literal
constants does each Python line's assembly actually embed?** It collects the
numeric immediate operands each mapped instruction carries and lists the distinct
values per Python line, plus a program-wide tally.

It reports two things:

- **Per Python line** — an `immediates` list: the distinct numeric constants that
  line's asm embeds, as `$N` labels ordered by value ascending (e.g.
  `["$-1", "$0", "$100"]`).
- **Program-wide** — an `immediate_summary` of
  `{ "immediate_totals": { "$N": instruction_count, … }, "distinct": N }`, the
  totals ordered by numeric value ascending (negatives first).

### Why this is its own lesson

The single most direct thing a learner can see is **their own literal travelling
through the compiler.** Write this:

```python
x = 5
```

and the assembly says:

```asm
movl    $5, -4(%ebp)
```

The `5` you typed is right there as `$5`. The addressing map would tell you this
line has "1 immediate operand"; the immediate map tells you the operand *is* `$5`.
That turns "Python constants become x86 immediates" from a claim into something
you read off the screen — the heart of pillar 1.

It also surfaces the constants the compiler introduces that are **not** in your
source — the `$0` of a `return 0` or a zero-initialiser, the `$1` of a loop step.
That gap between the code you wrote and the code that runs is exactly what a
reverse-engineer learns to read.

And it sharpens into pillar 2: **the constant a guard compares against is the bound
the whole check hinges on.** A comparison is where an off-by-one bound, a buffer
size that doesn't match the array it guards, or a sentinel that's quietly the
wrong value all hide — and the immediate map lists that magic number for you.

> **A note on comparison bounds.** gcc *normalises* a comparison constant: `if x <
> 100` is lowered to `cmpl $99, …` (because `x < 100 ⟺ x <= 99` for integers), and
> a `range(3)` loop test becomes `cmpl $2, …`. So the immediate on a comparison is
> the compiler's normalised bound, not necessarily the literal you typed — itself a
> genuine reverse-engineering lesson (the asm is one step removed from the source).
> A **direct assignment** literal, by contrast, is emitted verbatim: `x = 42` is
> always `movl $42, …`. The tests lean on that distinction (see below).

### What is *not* an immediate

Only **numeric** immediates are collected. A `$`-prefixed operand can also be the
*address* of a symbol or label:

```asm
pushl   $.LC0               # address of a string literal — a pointer, not a value
movl    $main, %eax         # address of a function
movl    $_shim_json_buf,…   # address of the json helper's buffer
```

These are pointers, not constant values, and are deliberately **excluded** so the
map reads as "the numbers in your program", not a jumble of relocation operands. A
displacement like the `8` in `8(%ebp)` is also not an immediate (it carries no
`$`) — that's the [stack-frame map](../stack-frame-map/README.md)'s job.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. A new `IMM:: N VALS` chip
   shows how many distinct numeric constants the whole program embeds; hover it to
   see the full list with per-value instruction counts (`$0 ×3 · $1 · $5`).
3. Hover any per-line chip: its tooltip now includes `imm: $5, $100` alongside the
   mix, registers, memory, addressing, and cost read-outs.
4. Experiment:
   - Start with `x = 5` — see `$5` appear on that line. Change the `5` and watch the
     immediate change with it: your literal, traced to the asm.
   - Write `if i < 100:` and note the comparison shows `$99`, not `$100` — the
     compiler's normalised bound (see the note above).
   - Add `print("hi")` and confirm **no** `$`-address of the string leaks into the
     map: only real numbers are listed.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and the
cost / mix / register / memory / addressing passes annotate each entry. The
immediate map is another independent pass over the **same** already-mapped
assembly — no extra compilation:

1. `immediate_values_in_instruction(text)` (in `backend/app/immediates.py`) returns
   the set of numeric immediate values on one asm line. It matches `$`-prefixed
   operands of the form `$<signed decimal>` or `$<signed 0x-hex>` with one regex
   (`\$(-?(?:0x[0-9a-fA-F]+|\d+))`); the hex alternative is listed first so `$0x10`
   reads as hex `16`, not decimal `0`. Symbolic operands (`$.LC0`, `$main`,
   `$_shim_json_buf`) never match — their first character after `$` is not a digit
   or sign — so address-of operands are excluded by construction.
2. `canonical_immediate(value)` renders a value as its `$N` label, always in
   **decimal**, so a hex immediate `$0x10` and a decimal `$16` fold to the same
   `$16` label.
3. `analyze_immediates(line_map, asm_lines)` runs after the other per-line passes,
   annotates each `line_map` entry with a sorted-ascending `immediates` list of
   `$N` labels, and returns
   `{ "immediate_totals": { "$N": count, … }, "distinct": N }`. `immediate_totals`
   counts, per value, the number of instructions that reference it (a value named
   twice in one instruction counts once), ordered by numeric value ascending — the
   same label-keyed, value-ordered shape as the stack-frame map's `slot_totals`. An
   out-of-range asm index is skipped defensively (never crashes, never counted).
4. These fields are declared on `LineMapping` (`immediates`, default `[]`) and a new
   `ImmediateSummary` in `backend/app/schemas.py` (`immediate_summary`, default
   `None`, so the pyghidra pipeline — which computes no per-line map — still
   validates), mirrored in the frontend types in `frontend/src/api.ts`, and rendered
   by `frontend/src/pages/Editor.tsx` as the `IMM::` chip and the enriched per-line
   tooltips.

**Relationship to the addressing map.** The two are complementary and independent:
`addressing_counts["immediate"]` is the *count* of immediate operands on a line;
`immediates` is the *set of their values*. A line can have `addressing` report `2
imm` while `immediates` reports `["$0", "$1"]` — same operands, two views.

## Scope

- **In scope:** a per-line `immediates` list of the distinct numeric constants a
  Python line's asm embeds, and a program-wide `immediate_totals` + `distinct`
  count in the API, plus a minimal editor read-out (chip + tooltip), for the
  transpile pipeline.
- **Out of scope:** symbolic / address-of immediates (`$.LC0`, `$main` — pointers,
  not values, excluded by design); any attempt to map a specific immediate back to
  the specific Python token that produced it beyond the line granularity the
  `.loc` mapping already gives; de-duplication of a value across different Python
  lines (each line reports its own distinct set); the pyghidra pipeline; any change
  to the transpiler or C/asm generation, or to the existing cost / mix / register /
  memory / addressing passes (the immediate map is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_immediate_value_map.py
```

The test file has two layers:

- **Unit tests** for `canonical_immediate` (decimal/negative/hex-folding),
  `immediate_values_in_instruction` (decimal, hex, negative, multiple-per-line,
  the displacement-is-not-an-immediate case, and every symbolic-operand exclusion),
  and `analyze_immediates` (per-line distinct values, per-instruction totals,
  numeric-ascending ordering with negatives first, per-instruction de-dup,
  out-of-range defensiveness, empty input, a zero-immediate line, and that the pass
  leaves the existing cost annotations intact). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response (`immediate_summary` present, distinct
  count equals the key count, **assignment literals appear verbatim** — `$5`,
  `$42`, `$7` — totals ordered numerically, a literal traces to its own line, and
  **no symbolic operand leaks** — every label parses as an integer). These are
  marked `needs_gcc` and **skip automatically** if `gcc` with `-m32` support is
  unavailable, so the suite still passes in a toolchain-less environment. They
  assert on assignment literals (emitted verbatim), never on comparison bounds
  (which gcc normalises — see the note above), so they are robust to how the
  compiler lowers arithmetic.
