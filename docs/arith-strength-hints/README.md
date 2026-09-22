# Arithmetic Strength Hints

> Feature branch: `feat/arith-strength-hints`

## What it teaches

**Mission pillars 1 and 2 — make the Python→asm mapping concrete, and train
engineers to spot inefficient assembly and understand the compiler's fix.**

The [cost](../asm-cost-analysis/README.md), [mix](../asm-instruction-mix/README.md),
[register](../register-footprint/README.md), [stack](../stack-frame-map/README.md)
and [memory](../asm-memory-traffic/README.md) passes all describe the **assembly**
a Python line compiled to. Strength hints work from the other end of the pipeline
— the **Python source** — to teach one specific thing the raw asm never spells
out: **which arithmetic the compiler strength-reduces, and which it cannot.**

It reports two things:

- **Per Python line** — a `strength_hints` list of `{ kind, message }` objects,
  empty when the line has no flagged arithmetic.
- **Program-wide** — a `strength_summary` of `{ hint_totals, hints }`, where
  `hint_totals` maps each kind to the number of lines carrying it and `hints`
  lists every flagged line.

The three kinds:

| kind        | Python                    | what `gcc -O0 -m32` emits                                   |
|-------------|---------------------------|-------------------------------------------------------------|
| `mul-pow2`  | `a * 8` (power-of-two)    | a single left shift `sal $3` — **no `imul`**                |
| `div-pow2`  | `n // 4`, `n % 8`         | arithmetic shift `sar` + sign fixup / bitwise `and` — **no `idiv`** |
| `div-var`   | `a / b` (runtime divisor) | a real, costly `idiv`                                        |

### Why this is its own lesson — and the surprise it corrects

A reasonable mental model says: "unoptimised code is literal, so `a * 8` becomes a
multiply and `n // 4` becomes a divide; only `-O2` would turn them into shifts."
**That model is wrong**, and the ASM pane proves it. Verified against this app's
real build (`gcc -O0 -m32`):

```asm
; b = a * 8      ->   sall  $3, %eax          (a left shift — no imul)
; c = a // 4     ->   leal  3(%eax), %edx     (sign bias for negatives)
;                     sarl  $2, %eax          (an arithmetic shift — no idiv)
; e = a % 8      ->   ...    andl $7, %edx     (a bitwise AND — no idiv)
; g = a // b     ->   idivl 12(%ebp)          (a real divide — the costly case)
```

Even with **no optimization**, the compiler already rewrites arithmetic by a
compile-time constant into shifts. The one thing it *cannot* reduce is a divide or
modulo by a **runtime value**: that stays a true `idiv`, the single most expensive
common integer instruction (tens of CPU cycles).

That contrast is the lesson. Strength hints name the exact instruction a learner's
line became (pillar 1 — "your `a * 8` is that `sal $3`"), and train the eye to
tell a cheap, compiler-supplied shift from a genuinely expensive `idiv` you should
keep out of hot loops (pillar 2). The `div-pow2` message also surfaces a classic
reverse-engineering gotcha: signed `//` is **not** a bare right shift — the extra
`lea`/`shr` you see is the sign-bias correction that makes rounding-toward-zero
work for negative operands.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Alongside the existing
   `COST::`, `MIX::`, `REGS::`, `MEM::` and `GLOSSARY::` chips, a new
   `HINTS:: N` chip shows how many lines carry a strength hint; hover it for the
   per-kind breakdown.
3. Any flagged per-line chip gets a cyan marker — `≪` (`mul-pow2`), `≫`
   (`div-pow2`), or `÷` (`div-var`) — and its tooltip spells out the full hint.
4. Experiment and confirm it against the ASM pane:
   - Write `y = x * 8`, click the line, and watch the highlighted assembly be a
     `sal`/`shl` — no `imul`. Change it to `y = x * b` and watch a real `imul`
     appear (a runtime multiply can't be reduced).
   - Write `q = n // 4` (a shift + sign fix) versus `q = n // d` (a real `idiv`)
     and compare the highlighted asm.

### Worked example

Compiling:

```python
a = 40
b = a * 8
c = a // 4
d = 3
e = a // d
```

- `b = a * 8` → `mul-pow2`: the multiply is a `sal $3`, no `imul`.
- `c = a // 4` → `div-pow2`: the divide is a `sar $2` plus a sign fixup, no `idiv`.
- `e = a // d` → `div-var`: the divisor is a runtime value, so this is a real
  `idiv`.

Program-wide: `hint_totals = { "mul-pow2": 1, "div-pow2": 1, "div-var": 1 }`.
Lines `a = 40` and `d = 3` carry no hint (a bare constant assignment does no
arithmetic).

## How it works technically

Unlike the asm-scan passes (which key off each `line_map` entry's `asm_lines`),
strength hints are derived from the **Python AST**, so they are stable across gcc
versions and never fire on a folded constant expression (`2 * 3`), where no
instruction reaches the pane at all. The pass lives in
[`backend/app/strength.py`](../../backend/app/strength.py):

1. `hint_for_binop(node)` classifies a single `ast.BinOp` — pure and side-effect
   free, so it is unit-testable without gcc:
   - `Mult` where one operand is a power-of-two literal **and the other operand
     is not itself a constant** → `mul-pow2` (a genuine runtime multiply gcc
     turns into a shift).
   - `Div` / `FloorDiv` / `Mod`:
     - divisor is a power-of-two literal **and the dividend is not a constant** →
       `div-pow2`;
     - divisor is **not a constant at all** (a variable, a call, …) → `div-var`
       (a real `idiv`);
     - divisor is a non-power-of-two *constant* (`a // 3`) → **no hint**: gcc
       rewrites that as a magic-number multiply, neither the clean shift case nor
       a true `idiv`, so it is deliberately left un-hinted;
     - both operands constant → **no hint** (folded at compile time).
   - `1` (`2**0`) and booleans are never treated as power-of-two operands.
2. `collect_hints(python_source)` walks the whole tree and attributes each hint to
   its operation's source line, de-duplicating repeats of the *same kind* on one
   line (so `a*8 + b*4` reports a single `mul-pow2`) while keeping distinct kinds,
   ordered `mul-pow2 → div-pow2 → div-var`. A syntax error yields an empty map
   (defensive only — this runs after a successful transpile).
3. `analyze_strength(line_map, python_source)` adds a `strength_hints` list to
   every mapped `line_map` entry (empty where nothing fires, mirroring how the
   memory pass always attaches `memory_counts`) and returns the program-wide
   `{ hint_totals, hints }` summary. It is called from `compile_python` in
   [`backend/app/compile.py`](../../backend/app/compile.py) after the asm-scan
   passes.
4. The fields are declared as `StrengthHint` on `LineMapping` and a new
   `StrengthSummary` on `CompileResponse` in
   [`backend/app/schemas.py`](../../backend/app/schemas.py) (defaulting to
   empty/`None`, so the pyghidra pipeline — which has no per-line mapping — still
   validates), mirrored in the frontend types in
   [`frontend/src/api.ts`](../../frontend/src/api.ts), and rendered by
   [`frontend/src/pages/Editor.tsx`](../../frontend/src/pages/Editor.tsx) as the
   `HINTS::` chip, the per-line cyan markers, and the enriched tooltips.

## Scope

- **In scope:** per-line strength hints and a program-wide summary in the API for
  the transpile pipeline, and a minimal editor read-out (chip + marker + tooltip).
  Hints cover power-of-two multiply, power-of-two divide/modulo, and runtime-value
  divide/modulo.
- **Out of scope:** a second `-O2` compile or an `-O0`-vs-`-O2` diff (the hints
  describe what `-O0` already does, from the AST, with no extra compilation);
  asm-scan-based detection (fragile across gcc versions); non-power-of-two
  *constant* divisors (gcc's magic-number multiply — an interesting but separate
  lesson, deliberately un-hinted to keep every hint verifiable against the pane);
  variable × variable multiply (already surfaced by the cost pass's `mul` flag);
  cycle-accurate timing; the pyghidra pipeline; and any change to the transpiler,
  the C/asm generation, or the existing cost/mix/register/stack/memory passes
  (this pass is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_strength_hints.py
```

The test file has two layers:

- **Unit tests** for `hint_for_binop` (every firing and silent expression shape:
  power-of-two multiply in either operand order, pow2 divide/floor-divide/modulo,
  runtime-divisor `idiv`, folded constant/constant expressions, non-pow2 multiply,
  non-pow2 *constant* divisors, multiply/divide by one, booleans, and unrelated
  operators), `collect_hints` (source-line attribution, same-kind de-duplication,
  distinct-kind ordering, arithmetic inside nested loops/functions, empty input,
  and syntax-error safety), and `analyze_strength` (line-map annotation, empty
  lists on unflagged lines, ordered zero-omitting totals, a regression check that
  existing fields are untouched, and an empty line-map). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert both that the summary reaches the API response **and** that the assembly
  the hint describes is what gcc actually emits: a `mul-pow2` line is a `sal`/`shl`
  with **no `imul`**, a `div-pow2` line is a `sar`/`shr` with **no `idiv`**, and a
  `div-var` line really contains an `idiv`. These are marked `needs_gcc` and
  **skip automatically** if `gcc` with `-m32` support is unavailable, so the suite
  still passes in a toolchain-less environment.
