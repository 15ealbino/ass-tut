# Integer Overflow Risk Hints

> Feature branch: `feat/int-overflow-hints`

## What it teaches

**Mission pillar 2 — train engineers to spot a vulnerable Python/C bug behind the
assembly.** (It also serves pillar 1: every hint points at the concrete `imul`
the Python line became.)

The [cost](../asm-cost-analysis/README.md), [mix](../asm-instruction-mix/README.md),
[register](../register-footprint/README.md), [stack](../stack-frame-map/README.md)
and [memory](../asm-memory-traffic/README.md) passes describe the **assembly** a
Python line compiled to. The [strength](../arith-strength-hints/README.md) pass
works from the **Python source** to teach *which arithmetic the compiler rewrites*
(a cost lens). This pass is the **correctness/security complement**: it teaches a
gap the pipeline silently introduces —

> **Python integers are arbitrary precision; the C `int` this transpiler emits is
> a fixed 32-bit value.**

Every Python `int` becomes a plain C `int` (that is the only integer type the
transpiler emits), and `gcc` targets `-m32`, so that `int` is 32-bit signed:
`-2,147,483,648 … 2,147,483,647` (`INT_MAX == 2147483647`). A multiplication whose
product passes `INT_MAX` **silently wraps** in the emitted C/asm, while the same
Python program would keep the exact big integer. No exception, no warning — the
asm result just quietly disagrees with Python. That is **CWE-190, Integer
Overflow or Wraparound** — the root of countless `malloc(count * size)` heap bugs.

It reports two things, exactly mirroring the strength pass's shape:

- **Per Python line** — an `overflow_hints` list of `{ kind, message }` objects,
  empty when the line has no flagged multiplication.
- **Program-wide** — an `overflow_summary` of `{ risk_totals, risks }`, where
  `risk_totals` maps each kind to the number of lines carrying it (zeros omitted,
  ordered) and `risks` lists every flagged line, ordered by `(py_line, kind)`.

### The two kinds

| kind             | Python                          | why it is flagged                                             |
|------------------|---------------------------------|---------------------------------------------------------------|
| `mul-overflow`   | `a * b`, `w * h`, `n * n`       | two **runtime** operands → a 32-bit `imul` whose product can exceed `INT_MAX` and wrap. The classic size-calculation overflow. |
| `mul-accumulate` | `fact *= i` **inside a loop**   | an in-place `*=` accumulator overflows astonishingly fast — `13!` alone already exceeds `INT_MAX`. |

### Why this is its own lesson — and the surprise it corrects

A reasonable mental model says: "the Python ran fine and printed a huge number, so
the compiled version computes the same thing." **That model is wrong**, and the
ASM pane proves it. A runtime multiply compiles to a 32-bit `imul`:

```asm
movl    -8(%rbp), %eax
imull   -4(%rbp), %eax      # 32-bit product — the top bits are simply gone
```

Run `fact = 1; for i in range(1, 21): fact *= i` in Python and you get
`2432902008176640000`. The transpiled C computes `20!` in a 32-bit `int`: the
`imul` truncates to 32 bits every iteration, and the result wraps to a
meaningless (often negative) number. **Same source, different answer** — because
one language has unbounded integers and the other does not. Signed overflow is
*undefined behaviour* in C; at `-O0` it wraps modulo 2³², which is what you will
observe.

## How a learner uses it

1. Write Python that multiplies in the editor — e.g. `area = w * h`, or a
   factorial loop `fact *= i`.
2. Compile. Flagged Python lines get a red overflow marker in the **TRACE**
   legend (`∞` for `mul-overflow`, `×↻` for `mul-accumulate`), and the legend bar
   shows an `OVERFLOW:: N` chip counting the flagged lines.
3. Hover a flagged line to read the hint, then click it to highlight the exact
   `imul` in the ASM pane. That `imul` is where a 32-bit truncation hides — the
   concrete instruction behind an abstract "it might overflow."

The lesson: the mapping tool is not just showing you *what* the code became, it is
showing you *where a whole class of real-world bugs lives* — the moment a
multiply's result stops fitting in 32 bits.

## Scope (deliberately tight)

Mirroring the strength pass's quiet-signal design, the hint stays high-signal:

- **Only multiplication is flagged** — the operation whose result grows fastest
  and the overwhelmingly common overflow site. Addition/subtraction overflow is
  real but needs operands already near `INT_MAX`; flagging every `+` would drown
  the signal, so it is intentionally **out of scope**.
- **`mul-overflow` requires both operands to be non-literal** (a genuine
  unknown × unknown). A multiply by a literal (`a * 8`, `count * 1024`) is left to
  the [strength](../arith-strength-hints/README.md) pass — multiplying by a small
  constant rarely overflows and would just be noise here. A negated literal
  (`a * -4`) counts as a literal, so it is not flagged either.
- **`mul-accumulate` requires the `*=` to be inside a loop.** A one-off `x *= 2`
  at top level is not the overflowing accumulator pattern. A function body resets
  the loop context — a `def` nested inside a loop does not inherit that loop.
- **Both-constant products (`1000 * 1000`) are never flagged** — gcc folds them at
  compile time, so no runtime overflow can arise.
- The hint is a **static heuristic**, not a proof: it flags *where* overflow can
  happen, not that it *will* for given inputs. It does not touch the `pyghidra`
  pipeline (no per-line Python→asm mapping to hang hints off).

## How it works technically

`backend/app/overflow.py` is a pure source-level AST pass — no assembly needed, so
it is stable across gcc versions.

- `risk_for_binop(node)` — pure classifier for a single `ast.BinOp`: returns
  `(KIND_MUL_OVERFLOW, message)` for a `Mult` with two non-literal operands, else
  `None`. Unit-testable without gcc.
- `collect_overflow_risks(source)` — an `ast.NodeVisitor` subclass walks the whole
  tree tracking loop-nesting depth. `BinOp` nodes are classified by
  `risk_for_binop`; an `AugAssign` with a `Mult` op is recorded as
  `mul-accumulate` only when loop depth > 0. Function bodies reset the depth.
  Returns `{ py_lineno: [ {kind, message}, … ] }`, de-duplicated per kind per line.
- `analyze_overflow(line_map, source)` — attaches an `overflow_hints` list to
  every mapped line and returns the program-wide `{ risk_totals, risks }` summary.
  Called from `compile.py` after the strength pass; serialized by the
  `OverflowSummary` / `OverflowHint` / `OverflowRiskEntry` models in `schemas.py`
  and surfaced on `CompileResponse.overflow_summary`.

The frontend (`frontend/src/api.ts`, `frontend/src/pages/Editor.tsx`) types the
new fields and renders the legend chip, per-line markers, and hover tooltips,
mirroring the strength-hint presentation.

## How to run its tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/test_overflow.py
```

Two layers (mirroring `tests/test_strength_hints.py`):

- **Pure unit tests** for `risk_for_binop` / `collect_overflow_risks` /
  `analyze_overflow` — no gcc, no assembly. These cover fire/silent cases, the
  negated-literal edge, dedup, kind ordering, loop-context gating (for/while/
  function-reset), and the program-wide summary.
- **End-to-end `/compile` tests** that exercise the real transpiler + gcc
  pipeline and assert both that the summary reaches the API and that the asm the
  hint describes (an `imul`) is actually what gcc emits. These are skipped
  automatically if `gcc` with `-m32` support is unavailable, so the suite still
  passes in a toolchain-less environment.
