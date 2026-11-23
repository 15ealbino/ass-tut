# Immediate-Constant Map

> Feature branch: `feat/immediate-constants`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** — and
**pillar 2 — train the reverse-engineering eye to read raw assembly.**

The sibling asm passes each read one axis of a Python line's compiled code: the
[instruction mix](../asm-instruction-mix/README.md) says *what kind* of work it
does, the [addressing map](../addressing-modes/README.md) says *what form* its
operands take, the [register footprint](../register-footprint/README.md) says
*which registers* it touches, and the [stack frame map](../stack-frame-map/README.md)
says *which %ebp slots*. This pass reads the axis a reverse-engineer reaches for
the instant a number catches their eye: **which literal values are baked into the
instruction stream itself** — the immediate (`$`-prefixed) operands.

Where the addressing map only *counts* immediate operands ("3 imm"), this pass
recovers the actual **values**:

| asm operand | recovered value |
|-------------|-----------------|
| `$42`       | `42`            |
| `$0x1f`     | `31`            |
| `$-1`       | `-1`            |

It reports two things:

- **Per Python line** — an `immediate_values` list: the distinct numeric
  immediates that line's asm embeds, sorted ascending, e.g. `[3, 42]`.
- **Program-wide** — an `immediate_summary` with `value_totals` (each distinct
  value → the number of instructions that embed it, ordered by value) and
  `distinct` (the count of distinct values), e.g.
  `{ "value_totals": { "3": 1, "42": 2 }, "distinct": 2 }`.

### Why this is its own lesson

Constant recovery is a **day-one reverse-engineering skill**. Embedded magic
numbers — buffer sizes, bit masks, sentinels, loop bounds, table lengths — are
often the single fastest way to understand what an unfamiliar (or stripped)
function does. This pass puts those constants in front of a learner and, crucially,
splits them into two tellable groups:

- **The literals you wrote.** Write `x = 42` and `$42` appears in the `movl` for
  that line. Finding *your own number* in the instruction stream is what turns
  the abstract "Python compiles to assembly" into something concrete you can
  point at (pillar 1).
- **The constants the compiler synthesised.** Even at `-O0`, gcc
  [strength-reduces](../arith-strength-hints/README.md) arithmetic by a
  compile-time power of two. So:

  ```python
  y = x * 8      # no imul — a left shift:   sall $3, %eax      ← $3 is synthesised
  z = n % 8      # no idiv — shifts + a mask: andl $7, %eax      ← $7 is synthesised
  ```

  The `3` and the `7` are **nowhere in the Python source** — the compiler
  invented them from your `8`. Learning to tell *"my 8"* (gone, folded into a
  shift distance) from *"the compiler's 3 and 7"* (present, and telling you a
  strength reduction happened) is exactly the codegen-fingerprint reading that
  makes a disassembly legible (pillar 2).

A sharper case appears the moment a divisor is **not** a power of two. `n % 7`
compiles to neither a clean shift nor an `idiv` but a *magic-number multiply*:

```asm
movl  $-1840700269, %edx    #  a "magic" reciprocal constant — where did THAT come from?
```

That huge, meaningless-looking immediate is the fingerprint of a compiler-chosen
division-by-constant trick. Recognising "that's a magic multiply, not a value the
programmer typed" is precisely the reflex this feature trains — and the same
reflex that flags a suspicious bound or sentinel in hostile code.

## How a learner uses it

1. Open the editor and write any Python the transpiler supports, e.g.:

   ```python
   x = 42
   y = x * 8
   z = y % 7
   ```

2. Compile. In the TRACE status bar a new **`IMM:: N`** chip shows how many
   distinct numeric constants the program embedded; hover it to see every value
   with its instruction count (smallest first) and a plain-English note on
   source-vs-synthesised constants.
3. Click a Python line (or hover its TRACE chip). Its tooltip now carries an
   `— imm: $3 $42`-style read-out of the exact constants *that line* bakes into
   its assembly. Compare `x = 42` (embeds `$42`) against `y = x * 8` (embeds the
   synthesised shift count `$3`, **not** `$8`).

## How it works technically

The pass lives in [`backend/app/immediates.py`](../../backend/app/immediates.py)
and follows the same shape as the other per-line analysers: a pure, syntactic
scan over the already-built display assembly that mutates `line_map` in place and
returns a program-wide summary.

- **`parse_immediate(operand)`** — returns the signed integer value of a numeric
  immediate (`$42 → 42`, `$0x1f → 31`, `$-0x10 → -16`) or `None` for anything
  else. A single anchored regex, `^\$(-?(?:0[xX][0-9a-fA-F]+|\d+))$`, means a
  **symbolic / address immediate** (`$.LC0`, `$main`, `$sym+4`) does not match —
  it is an address, not a value a learner can reason about (see *Out of scope*).
- **`immediates_in_instruction(text)`** — splits one asm line's operands (sharing
  the addressing pass's parenthesis-aware splitter, so a scaled-index operand's
  internal `,4` is never mistaken for an immediate) and returns the distinct
  numeric immediates on that line, sorted. Labels, directives and operand-less
  instructions contribute nothing.
- **`analyze_immediates(line_map, asm_lines)`** — for every mapped line, unions
  its instructions' immediates into `immediate_values` and tallies `value_totals`
  (counting, per value, the number of instructions that embed it — a value named
  twice in one instruction counts once, mirroring the register and addressing
  passes). Out-of-range asm indices are skipped defensively.

The pass is wired into
[`backend/app/compile.py`](../../backend/app/compile.py)'s `compile_python`
alongside the other analysers, serialised via `ImmediateSummary` /
`LineMapping.immediate_values` in
[`backend/app/schemas.py`](../../backend/app/schemas.py), and surfaced in the
editor by the `IMM::` chip and per-line tooltip in
[`frontend/src/pages/Editor.tsx`](../../frontend/src/pages/Editor.tsx) (types in
[`frontend/src/api.ts`](../../frontend/src/api.ts)).

### Scope

- **In scope:** numeric immediate operands (decimal and `0x`-hex, signed) in the
  transpile pipeline — recovered per line and program-wide, with the API payload
  and a minimal editor read-out (chip + tooltip).
- **Out of scope:** symbolic / address immediates (`$.LC0`, `$main`) — these are
  addresses, not values, and under this app's `-m32` PIC build string/function
  addresses are loaded through the GOT rather than as `$` immediates anyway;
  floating-point constants (gcc materialises `double`s in `.rodata`, not as `$`
  immediates); which *source* literal a given immediate came from (the pass
  recovers values, not provenance — the source-vs-synthesised split is taught,
  not computed, because matching asm constants back to source tokens is
  unreliable once strength reduction and constant folding have run); the pyghidra
  pipeline; and any change to the transpiler or C/asm generation, or to the
  existing per-line passes (this pass is orthogonal and purely additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_immediate_constants.py
```

The test file has two layers:

- **Unit tests** for `parse_immediate` (decimal/hex/signed values plus the
  non-numeric rejections: symbolic immediates, registers, memory operands, bare
  symbols, and malformed `$`/`$0x` forms), `immediates_in_instruction` (basic
  recovery, strength-reduction constants, sorted-and-distinct results, that a
  scaled-index operand yields no immediate, and that labels / directives /
  operand-less instructions contribute nothing), and `analyze_immediates`
  (per-line annotation, per-instruction totals, the value-twice-in-one-instruction
  rule, out-of-range defensiveness, empty input, a no-immediate line, and the
  totals-equal-sum-over-instructions invariant). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response: `immediate_summary` is present and
  every line carries an `immediate_values` list; a source literal (`x = 42`)
  appears as `$42`; a power-of-two multiply (`x * 8`) surfaces the synthesised
  shift count `3`; the per-line values are consistent with `value_totals`; and an
  unsupported construct still returns HTTP 422. These are marked `needs_gcc` and
  **skip automatically** if `gcc` with `-m32` support (including the 32-bit libc
  headers the real pipeline needs) is unavailable, so the suite still passes in a
  toolchain-less environment.
