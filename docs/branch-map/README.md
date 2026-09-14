# Control-Flow Branch Map

> Feature branch: `feat/branch-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping clearer** (with a strong
pillar 2 / reverse-engineering payload).

Python has no `goto`, so it is easy to forget that at the machine level `for`,
`while`, `if`, `elif`, `else`, `break` and `continue` are **all just jumps**. The
branch map surfaces, for each Python line, the jump instructions its assembly
emits and — the teaching payload — whether each jump goes **backward** or
**forward**:

- A **backward** jump (a *back-edge*) targets an earlier address. That is
  literally how a `for`/`while` loop repeats work. The number of back-edges in a
  program is, in effect, the number of loops.
- A **forward** jump skips over code. That is how `if`/`elif`/`else`, `break`,
  `continue`, and the short-circuit in `and`/`or` bail out of a region.

It reports two things:

- **Per Python line** — a `branches` list, each element
  `{ mnemonic, target, direction, conditional }`, e.g.
  `{ "mnemonic": "jle", "target": ".L4", "direction": "back", "conditional": true }`.
- **Program-wide** — a `branch_summary`:
  `{ total_jumps, conditional, unconditional, back_edges, forward_edges }`.

### Why this is its own lesson

The [instruction mix](../asm-instruction-mix/README.md) already counts how many
`branch`-category instructions a line has, and the
[glossary](../asm-glossary/README.md) explains what `jle` *means*. Neither tells
you **where control goes**. Reading loop and branch *structure* off a flat
instruction stream — finding the back-edges that mark loops, and the forward
conditional jumps that form the if/else skeleton — is a day-one
reverse-engineering task. A disassembler recovers a function's control-flow graph
exactly this way. The branch map makes that recovery explicit on code you wrote,
so the abstract "loops are back-edges" becomes something you can see next to your
own `while` line.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - `COST:: N INSTR` — total instruction count (cost feature).
   - `MIX:: …`, `REGS:: …`, `MEM:: …` — the existing per-program signals.
   - A new `BRANCH:: N jmp · N loop · N fwd` chip shows the program's total jumps,
     how many are loop back-edges, and how many are forward skips. Hover it for the
     full explanation.
   - Hover any per-line chip: its tooltip now includes
     `branch: jle→.L4 loop · jmp→.L2 fwd` alongside the instruction count, mix,
     registers, memory traffic, and expensive-op flags.
3. Experiment. Write a straight-line program and watch `back_edges` stay `0`. Add
   a `for` or `while` loop and watch exactly one back-edge appear. Add an `if`
   inside it and watch a forward conditional jump appear on the `if` line.

### Worked example

Compiling:

```python
x = 0
for i in range(5):
    if i > 2:
        x = x + i
```

- The **loop header** line emits a forward `jmp` to the loop-test label, plus a
  backward conditional jump (the **back-edge**) that re-enters the body — this is
  what makes the loop repeat.
- The **`if i > 2`** line emits a forward conditional jump (`jle`/`jg`) that
  **skips** the body when the condition is false.

Program-wide you get one `back_edge` (one loop) and two `forward_edges`
(the jump-to-test and the if-skip). Read straight off the assembly, that is the
program's control-flow skeleton.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost/mix/register/stack/memory passes annotate each entry. The branch map is
another **independent pass over the same already-mapped assembly** — no extra
compilation:

1. `_collect_labels(asm_lines)` (in `backend/app/compile.py`) scans the filtered
   display assembly once and maps every label name to the 1-indexed line where it
   is **defined** (gcc emits labels at column 0, e.g. `.L2:`). This is what lets
   direction be decided by position.
2. `_jump_kind(mnemonic)` classifies a mnemonic as `"uncond"` (the unconditional
   `jmp`), `"cond"` (every conditional jump `je`/`jne`/`jl`/`jle`/… and the
   `loop`/`loope`/`loopne` family, which branch on `%ecx`), or `None` (not a
   jump). It is matched by prefix so size-suffixed forms are covered, with `jmp`
   checked before the generic `j` catch-all. **`call` is deliberately excluded** —
   it is function-call overhead (already covered by the cost/mix passes), not
   intra-function control flow.
3. `_branch_at(text, asm_no, labels)` describes the jump on one line as
   `{ mnemonic, target, direction, conditional }`. Direction is decided purely by
   position: the target label's definition line vs. the jump's own line —
   `target_line <= asm_no` is a **back**-edge, otherwise **forward**. Two
   defensive cases never fabricate a direction: an indirect jump (`jmp *%eax`, no
   static target) is `"indirect"`, and a target label not present in the emitted
   asm is `"unknown"`. Neither occurs for the transpiler's supported subset, but
   both are handled so the map is never wrong.
4. `analyze_branches(line_map, asm_lines)` runs after the other per-line passes,
   adds a `branches` list to each `line_map` entry (in stream order), and returns
   the program-wide `branch_summary`. It counts only jumps that are mapped to a
   Python line (same convention as the other passes) and skips any out-of-range
   asm index defensively.
5. These fields are declared as `BranchEdge` on `LineMapping` and a new
   `BranchSummary` on `CompileResponse` in `backend/app/schemas.py` (defaulting to
   an empty list / `None`, so the pyghidra pipeline — which computes no per-line
   branch map — still validates), mirrored in the frontend types in
   `frontend/src/api.ts`, and rendered by `frontend/src/pages/Editor.tsx` as the
   `BRANCH::` chip and the enriched per-line tooltips.

**Invariants:** `conditional + unconditional == total_jumps` always;
`back_edges + forward_edges` equals `total_jumps` except for the rare
indirect/unknown jumps the supported subset never emits.

## Scope

- **In scope:** per-line jump lists (mnemonic, target label, direction,
  conditional flag) and a program-wide jump/back-edge/forward-edge summary in the
  API, plus a minimal editor read-out (chip + tooltip), for the transpile
  pipeline.
- **Out of scope:** rendering a full control-flow-graph diagram; naming *which*
  Python construct produced a jump (loop vs. `break` vs. short-circuit — the map
  shows the direction, not the source construct); reconstructing basic blocks or
  dominators; `call`/`ret` (function-call control flow, covered by the cost/mix
  passes); indirect jump-table analysis (the supported subset emits none); the
  pyghidra pipeline; any change to the transpiler or C/asm generation, or to the
  existing analysis passes (the branch map is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_branch_map.py
```

The test file has two layers:

- **Unit tests** (no toolchain) for `_jump_kind` (the whole jump family plus the
  non-jumps `call`/`mov`/`ret`/… that must return `None`), `_collect_labels`
  (name→line mapping, first-definition-wins, ignoring directives/instructions),
  `_branch_at` (forward, backward, unconditional, the `<=` boundary, indirect,
  unknown-label, and the non-jump/label/directive lines that return `None`), and
  `analyze_branches` (a hand-written loop-with-`if` asm block matching real gcc
  output, the `conditional + unconditional == total_jumps` invariant, empty-jump
  lines, out-of-range asm indices, an empty line_map, and a regression check that
  the pass only adds the `branches` field).
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response (`branch_summary` present, straight-
  line code has no back-edges, a loop produces a back-edge, an `if` produces a
  forward conditional, and a rejected construct still returns HTTP 422). These are
  marked `needs_gcc` and **skip automatically** if `gcc` with `-m32` support is
  unavailable, so the suite still passes in a toolchain-less environment.
