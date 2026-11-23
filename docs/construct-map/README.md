# Construct Map

> Feature branch: `feat/construct-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** — with a
direct bridge to **pillar 2 — reading control flow off raw assembly.**

Every other per-line pass in the compile pipeline works from the *far* end,
scanning the generated assembly: the
[instruction mix](../asm-instruction-mix/README.md),
[register footprint](../register-footprint/README.md),
[stack frame map](../stack-frame-map/README.md),
[memory traffic](../asm-memory-traffic/README.md),
[branch maps](../branch-flow-map/README.md), and
[addressing modes](../addressing-modes/README.md) all read a line's
`asm_lines`. This pass works from the *near* end — the Python AST — and answers
the most elementary question of all, the one a learner asks before any asm
detail: **what kind of statement is this line, and what shape of machine code
does that kind become?**

It classifies each mapped Python line into one construct kind:

| Kind | Python | Asm shape it lowers to |
|------|--------|------------------------|
| `funcdef` | `def f(...):` | prologue/epilogue — `push %ebp` … `leave; ret` |
| `classdef` | `class C:` | struct layout plus its methods |
| `assign` | `x = …` | compute, then store to a stack slot |
| `augassign` | `x += …` | load · compute · store round-trip through one slot |
| `for` | `for i in range(…):` | **backward** conditional jump (the loop back-edge) |
| `while` | `while …:` | test, then a **backward** conditional jump |
| `if` | `if …:` / `elif …:` | **forward** conditional jump around the body (branch-around) |
| `call` | `print(x)` | push args, call, read the result |
| `return` | `return …` | load the value into `%eax`, then `leave; ret` |
| `break` | `break` | an **unconditional** jump out of the loop |
| `continue` | `continue` | a jump back to the loop test |
| `import` | `import math` | a C shim — no code of its own at the use site |
| `expr` | a bare expression | evaluated, result discarded |

It reports two things:

- **Per Python line** — a `construct_kind` string (empty when the line is not one
  of the named statement kinds).
- **Program-wide** — a `construct_totals` map of `kind → number of mapped lines`,
  in display order, e.g. `{ "funcdef": 1, "assign": 2, "for": 1, "if": 1 }` — a
  one-glance read of the program's structural shape.

### Why this is its own lesson

Naming the construct is only half of it; the payload is that **each kind lowers
to a recognisable asm shape**, so the label points the eye straight at that shape
in the ASM pane:

- A **`for`/`while`** becomes a **backward** conditional jump — the loop
  back-edge that returns control to the test at the top.
- An **`if`/`elif`** becomes a **forward** conditional jump that skips *around*
  its body — the "branch-around" pattern.
- A **`def`** becomes a prologue/epilogue; a **`return`** loads `%eax` then
  returns; a **`break`** is an unconditional jump straight out of the loop.

Reading those shapes off a disassembly — *loop = backward branch, if/else =
forward-around* — is a day-one reverse-engineering skill, and the wrong shapes
are exactly the bugs pillar 2 trains you to spot: a backward branch with no exit
condition (an infinite loop), a forward branch that skips a check (a sanitiser
bypass). The construct map is the Rosetta stone that pairs each Python keyword
with the shape it produces, and it pairs naturally with the
[branch flow map](../branch-flow-map/README.md), which confirms the forward /
backward direction in the asm itself.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Alongside the existing
   `COST::`, `MIX::`, `REGS::`, `MEM::`, `SENSE::`, `ADDR::`, and `HINTS::`
   chips, a new `FORM:: 1 def · 2 assign · 1 for · 1 if` chip shows the
   program's construct breakdown.
3. Hover any per-line chip: its tooltip now opens with `form: for (range loop →
   a backward conditional jump …)`, pairing that line's keyword with the asm
   shape to go look for.
4. Experiment:

   ```python
   def total(n):
       s = 0
       for i in range(n):
           s += i
           if i == 2:
               break
       return s
   ```

   The `for` line is tagged `form: for` (look for the backward jump), the `if`
   line `form: if` (the forward branch-around), the `break` line `form: break`
   (the unconditional jump out), and `return` the `%eax` load — the control-flow
   skeleton of the function, readable before you decode a single operand.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` and runs a stack of per-line passes
over it. The construct map is another such pass, but — like the
[arithmetic strength hints](../arith-strength-hints/README.md) — it keys off the
**Python source**, not the assembly, so it needs no gcc and is stable across
toolchains. It lives in its own module, `backend/app/constructs.py`:

1. `classify_statement(node)` maps one AST *statement* node to its kind (or
   `None` for a statement this pass does not name, e.g. `pass`). It is pure and
   unit-testable with no gcc. A bare expression statement is `call` when its
   value is a `Call` (the common `print(x)`) and `expr` otherwise.
2. `collect_constructs(source)` walks the AST and returns `{ lineno: kind }`,
   attributing each statement to its header line (an `elif` is an `If` node on
   its own line; when two statements share a line the first seen wins). A syntax
   error yields an empty map rather than raising (defensive — this runs after a
   successful transpile).
3. `analyze_constructs(line_map, source)` adds a `construct_kind` string to each
   `line_map` entry (empty when unnamed) and returns
   `{ "construct_totals": { kind: mapped_line_count, … } }` in the fixed display
   order, zero kinds omitted. **Totals count only mapped lines**, so the summary
   is the shape of exactly the code shown in the panes.
4. These fields are declared on `LineMapping` (as `construct_kind` — named so to
   avoid shadowing pydantic `BaseModel`'s deprecated `construct` classmethod)
   and a new `ConstructSummary` in `backend/app/schemas.py`, defaulting to empty
   so the pyghidra pipeline — which computes no per-line construct — still
   validates. They are mirrored in `frontend/src/api.ts` and rendered by
   `frontend/src/pages/Editor.tsx` as the `FORM::` chip and the enriched per-line
   tooltip, where the human label and the one-line asm-shape hint for each kind
   live (the API carries only the compact machine-readable kind, matching how the
   other passes keep their presentation strings on the frontend).

## Scope

- **In scope:** a per-line construct classification and a program-wide
  per-kind tally in the API, and a minimal editor read-out (chip + the asm-shape
  tooltip), for the transpile pipeline.
- **Out of scope:** nesting depth / block structure (a separate concern); which
  specific branch instructions a line actually emits (the
  [branch flow map](../branch-flow-map/README.md) reports those from the asm);
  expression-level classification (only the statement a line *is* gets a kind,
  not the sub-expressions inside it); verifying that the claimed asm shape is
  present (the hint is a teaching pointer, not an assertion about the emitted
  code); the pyghidra pipeline; any change to the transpiler, the C/asm
  generation, or the existing per-line passes (this pass is orthogonal and purely
  additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_constructs.py
```

The test file has three layers:

- **Unit tests** for `classify_statement` (every supported statement kind, the
  `call` vs `expr` split, and that non-statements / unnamed statements like
  `pass` return `None`), `collect_constructs` (per-line kinds, `elif` on its own
  line, first-statement-wins on a shared line, and the syntax-error-is-empty
  guard), and `analyze_constructs` (annotation, display-ordered totals,
  empty-string for unnamed kinds, mapped-lines-only counting, and empty input).
  These need no toolchain.
- **Transpile-integration tests** that run the **real transpiler** (Python AST →
  C, which needs no gcc), build a `line_map` from its actual py→C mapping, and
  assert the construct classification lines up line-for-line on a full function
  with a loop, an `if`, a `break`, and a `return`. This exercises the whole
  classification path end-to-end in a toolchain-less environment.
- **End-to-end `/compile` tests** that run the full transpiler + gcc pipeline and
  assert `construct_summary` is present, every line carries a `construct_kind`,
  and a loop / assignment / augmented-assignment program is tagged correctly.
  These are marked `needs_gcc` and **skip automatically** if `gcc` with `-m32`
  support is unavailable, so the suite still passes without the toolchain.
