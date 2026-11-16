# Immediate-Operand Map ("constant map")

> Feature branch: `feat/immediate-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** (now at the
*value* level) — and **pillar 2 — train the reverse-engineering eye to read raw
assembly.**

The sibling asm passes each answer a neighbouring question about a Python line's
compiled code: the [instruction mix](../asm-instruction-mix/README.md) says *what
kind* of work it does, the [register footprint](../register-footprint/README.md)
says *which registers* it touches, the [stack frame map](../stack-frame-map/README.md)
says *which %ebp slots*, and the [addressing-mode map](../addressing-modes/README.md)
says what *form* each operand takes — including a **count** of how many operands
are immediates. This pass answers the question that count only gestures at: **what
*are* the immediate constants, and what do they mean?**

Every immediate operand (an AT&T operand beginning with `$`) that a Python line
maps to is sorted into exactly one of three kinds, and — for the numeric kinds —
its integer value is recovered:

| Kind | Meaning | Example operand | Value |
|------|---------|-----------------|-------|
| `decimal` | a plain numeric literal | `$5`, `$-1`, `$0` | `5`, `-1`, `0` |
| `hex` | a hexadecimal numeric literal | `$0x10`, `$-0x1` | `16`, `-1` |
| `symbol` | an **ADDRESS** constant, not a value | `$.LC0`, `$main` | *(none)* |

It reports two things:

- **Per Python line** — an `immediate_counts` map with the nonzero kinds in
  display order (`decimal` < `hex` < `symbol`), e.g. `{ "decimal": 2, "symbol": 1 }`,
  plus an `immediate_values` list of the **distinct numeric values** the line
  embeds (decimal + hex folded to `int`, sorted ascending), e.g. `[0, 5]`.
- **Program-wide** — an `immediate_totals` map summing every line's operand
  counts, and a `distinct_values` list of every numeric value the whole program
  bakes in, e.g. `{ "immediate_totals": { "decimal": 6, "symbol": 2 }, "distinct_values": [0, 1, 5, 42] }`.

### Why this is its own lesson

The [addressing-mode map](../addressing-modes/README.md) already tells you an
operand *is* an immediate. This pass tells you **which constant it is** — and
splits a numeric *value* from a symbolic *address*. That distinction is the whole
point:

- **Pillar 1 — read your own literal in the machine code.** When you write
  `x = 42`, the compiler bakes that literal straight into the assembly:

  ```asm
  movl $42, -8(%ebp)      #  x = 42  — your "42" is right there as $42
  ```

  The other passes show the *shape* of the lowering; this one lets you point at
  the exact constant you typed and find it in the disassembly. `42` lands in that
  line's `immediate_values` and in the program's `distinct_values`.

- **Pillar 2 — "is this a value, or an address?" is the first read an RE makes.**
  x86 writes both numeric values and pointers as `$...` immediates, but they mean
  completely different things. A `decimal`/`hex` immediate is a **value** — a
  magic number, a buffer size, a sentinel, a syscall number. A `symbol` immediate
  is an **address** — most commonly `$.LC0`, the address of a string literal or
  `printf` format string living in read-only data:

  ```asm
  movl $.LC0, (%esp)      #  pass the address of the format string to printf
  call printf
  ```

  Seeing a `symbol` immediate tells you "a pointer into rodata is being formed
  here" — exactly the read a reverse-engineer performs on an operand. Splitting it
  out from the numeric values is what the raw addressing count cannot do.

- **Pillar 2 — the compiler writes constants you never typed.** Not every
  immediate came from your source. The `$0` of an implicit `return 0`, loop step
  constants, and frame arithmetic are all synthesized by the compiler. Surfacing
  *every* baked-in constant — not just the ones you wrote — trains the eye to tell
  source constants from compiler-introduced ones, the precise skill you need when
  a disassembly's constants don't line up with the code you expected.

## How a learner uses it

1. Open the three-pane editor, type some Python, and hit compile.
2. In the legend bar above the panes, find the **`IMM::`** chip. It shows the
   program-wide kind breakdown (e.g. `IMM:: 6 dec · 2 sym`); hover it for the full
   explanation and the list of every distinct numeric value the program baked in.
3. Hover any Python line in the trace strip. Its tooltip includes an
   **`imm:`** segment naming the kinds on that line and, in brackets, the distinct
   numeric values it embeds — e.g. `imm: 1 dec [42]` on `x = 42`.
4. Try the contrast that makes the lesson land:
   - `x = 42` → the value `42` appears; a pure numeric program has **no** `symbol`
     immediate.
   - `print("hello")` → a `symbol` immediate appears — the address of the format
     string in rodata.
   - Add a `return`-bearing function → watch the synthesized `$0` show up as a
     constant you never typed.

## How it works technically

The pass lives in [`backend/app/immediates.py`](../../backend/app/immediates.py)
and runs in [`compile.py`](../../backend/app/compile.py)'s `compile_python`, over
the same already-filtered display assembly and `line_map` that every sibling pass
uses. It is **purely syntactic** on the AT&T operand text — no second gcc pass, no
source coupling:

- `classify_immediate(operand)` → `"decimal"` / `"hex"` / `"symbol"`, or `None`
  for any operand that does not begin with `$`. That `None` (rather than a
  catch-all bucket) is what guarantees a register or memory operand is never
  miscounted as a constant. Hex is tested before decimal so `$0x10` is not misread.
- `immediate_int_value(operand)` recovers the `int` for a `decimal`/`hex`
  immediate and returns `None` for a `symbol` (an address has no numeric value).
  Parsing is anchored by the classifier, so a malformed body cannot raise here.
- `immediates_in_instruction(text)` splits one instruction's operands (keeping a
  scaled-index operand's internal commas intact) and yields `(kind, value)` for
  each immediate, skipping labels, directives (`.long 42` — a bare number, not a
  `$`-immediate) and operand-less instructions.
- `analyze_immediates(line_map, asm_lines)` walks each Python line's mapped asm
  (defensively skipping out-of-range indices), writes `immediate_counts` and
  `immediate_values` onto the entry, and returns the `{immediate_totals,
  distinct_values}` summary. Counts are of **operands** (so the per-line counts
  sum to the totals); values are **distinct** per line and program-wide.

The result is surfaced through [`schemas.py`](../../backend/app/schemas.py)
(`LineMapping.immediate_counts` / `immediate_values`, `ImmediateSummary`,
`CompileResponse.immediate_summary`) and
[`frontend/src/api.ts`](../../frontend/src/api.ts), and rendered by
[`Editor.tsx`](../../frontend/src/pages/Editor.tsx) as the `IMM::` chip and the
per-line `imm:` tooltip segment.

Like every per-line pass, the immediate map is computed only for the **transpile**
pipeline; the `pyghidra` pipeline has no per-line Python→asm mapping, so
`immediate_summary` is `None` and the per-line fields stay empty there.

## How to run its tests

The tests are in
[`backend/tests/test_immediate_map.py`](../../backend/tests/test_immediate_map.py),
in two layers (mirroring the sibling passes):

- **Unit** — pure-function tests for `classify_immediate`, `immediate_int_value`,
  `immediates_in_instruction`, and `analyze_immediates`. These need **no gcc** and
  run everywhere.
- **End-to-end** — `/compile` tests asserting a source literal appears as a
  numeric immediate value and that `print("...")` emits a symbolic immediate.
  These are **skipped automatically** if gcc with `-m32` support is unavailable,
  so the suite still passes in a toolchain-less environment.

```bash
cd backend
pip install -r requirements.txt
pytest tests/test_immediate_map.py          # just this feature
pytest                                       # the whole suite
```

The `/compile` pipeline compiles with `gcc -S -O0 -m32`; running the e2e layer
needs a gcc with 32-bit support (on Debian/Ubuntu, the `gcc-multilib` /
`libc6-dev-i386` packages). Without it those four e2e tests report `SKIPPED`
rather than failing.
