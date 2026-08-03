# Register Footprint

> Feature branch: `feat/register-footprint`

## What it teaches

**Mission pillars 1 & 2 — make the Python → C → assembly mapping concrete, and
train the eye to spot non-obvious assembly behaviour.**

The existing [cost analysis](../asm-cost-analysis/README.md) answers *how much*
work a Python line's assembly does (instruction count + expensive-op flags), and
the [instruction mix](../asm-instruction-mix/README.md) answers *what kind* of
work it is (mem / compute / branch / call / stack). The register footprint
answers the third question — **where** the work happens: which x86 registers
each Python line's assembly actually touches.

It reports two things:

- **Per Python line** — the set of canonical 32-bit registers that line's mapped
  instructions reference, e.g. `%eax`, `%ebp`, `%edx`.
- **Program-wide** — a `register_totals` map: for each register, how many
  instructions across the whole program reference it.

### Why this is its own lesson

Two payoffs, one per pillar:

1. **The shape of `-O0` code becomes visible (pillar 1).** At `gcc -O0` every
   value lives on the stack and is shuttled through a tiny set of registers.
   Seeing `%eax` light up on nearly every line — and `%ebp` on every stack-slot
   access — makes the accumulator-and-frame-pointer shape of unoptimised code
   real in a way an instruction count never does.

2. **Implicit registers — the disassembly gotcha (pillar 2).** Some instructions
   read or write registers that never appear in the operand text. The headline
   case is **integer division**: `q = a // b` compiles to

   ```asm
   cltd            # sign-extend %eax into %edx  (no operands at all)
   idivl %ecx      # dividend is the %edx:%eax pair; %ecx is only the divisor
   ```

   The dividend is the 64-bit `%edx:%eax` pair, and the remainder comes back in
   `%edx` — so this line **touches `%edx` even though your Python (and the
   operand text) never names it**. Misreading exactly this kind of implicit
   register use is a classic reverse-engineering mistake. The footprint surfaces
   those hidden registers right next to the explicit ones.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - `COST:: N INSTR` — total instruction count (cost feature).
   - `MIX:: mem N · compute N …` — program-wide instruction mix (mix feature).
   - A new `REGS:: %eax N · %edx N …` chip shows how many instructions touch
     each register, in a stable accumulator-first order.
   - Hover any per-line chip: its tooltip now includes
     `regs: %eax, %edx …` alongside the instruction count, mix, and expensive-op
     flags.
3. Experiment. Write `y = a // b` and watch `%edx` appear even though you never
   typed it. Add more locals and watch `%ebp` (the frame pointer) dominate the
   totals — every spill and reload goes through a `%ebp`-relative slot.

### Worked example

Compiling:

```python
def divmod_ish(a, b):
    q = a // b
    return q
```

The `q = a // b` line maps to `cltd` + `idivl %ecx`, so its footprint is:

```
registers: ['eax', 'ecx', 'edx']
```

`%ecx` is the explicit divisor; `%eax` and `%edx` are the implicit dividend
pair. That `%edx` is the teachable surprise — it is present because of how
`idiv` works, not because of anything visible in the source.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost/mix pass annotates each entry with `asm_count` / `flags` /
`category_counts`. The register footprint is a second, independent pass over the
**same** already-mapped assembly — no additional compilation:

1. `canonical_register(token)` (in `backend/app/compile.py`) folds any register
   spelling to its canonical 32-bit family: `%al`/`%ax` → `eax`, `%dx` → `edx`,
   `%bp` → `ebp`, the x87 stack registers `%st`/`%st(0)`..`%st(7)` → `st`, and
   the 64-bit spellings (`%rax` → `eax`) for robustness. An unrecognised token
   (e.g. `%xmm0`) is kept as-is so it is still counted, never silently dropped.
2. `_registers_in_instruction(text)` extracts every `%`-prefixed operand via a
   regex, folds each to canonical form, and adds any **implicit** registers the
   mnemonic touches (`_implicit_registers`). The implicit table is deliberately
   conservative — only always-correct cases:
   - `idiv*` / `div*` (integer division) → implicit `%eax`, `%edx`.
   - `cltd` / `cdq` / `cwd` / `cqto` (sign-extend the accumulator into the data
     register) → implicit `%eax`, `%edx`.
   - The one-operand `mul`/`imul` also use `%edx:%eax`, but gcc `-O0` emits the
     two/three-operand `imul` form for `a * b` (no `%edx`), so multiply is left
     to its explicit operands — no false `%edx` claim.
   - SSE division (`divsd`/`divss`) is excluded by the integer-suffix check
     (`div` followed by `b`/`w`/`l`/`q`/nothing), since it uses `%xmm`, not
     `%edx:%eax`.
3. `analyze_registers(line_map, asm_lines)` runs after `analyze_cost`, adds a
   sorted `registers` list to each `line_map` entry, and returns
   `{ "register_totals": { reg: instruction_count } }` — both in the stable
   `eax → ebx → ecx → edx → esi → edi → ebp → esp → eip → st` order.
4. These fields are declared on `LineMapping` and a new `RegisterSummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline — which
   computes no per-line footprint — still validates), mirrored in the frontend
   types in `frontend/src/api.ts`, and rendered by `frontend/src/pages/Editor.tsx`
   as the `REGS::` chip and the enriched per-line tooltips.

**Invariant:** `register_totals` counts each register once per instruction that
references it (a register named twice in one instruction counts once), so a
total reads directly as "how many instructions touch this register". A
defensively-skipped out-of-range asm index contributes nothing.

## Scope

- **In scope:** the *set* of registers each already-mapped Python line touches
  (explicit operands + always-correct implicit registers), a per-line list and a
  program-wide total in the API, and a minimal editor read-out.
- **Out of scope:** precise per-operand read-vs-write *direction* (the footprint
  reports the touched set, not data-flow direction); XMM/segment/control
  registers beyond generic bucketing; any change to the transpiler or C/asm
  generation; cycle-accurate timing; the pyghidra pipeline; reworking the
  existing cost/mix passes (the footprint is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_register_footprint.py
```

The test file has two layers:

- **Unit tests** for `canonical_register` (every family, sub-register folding,
  64-bit spellings, x87 stack, case-insensitivity, unknown-token pass-through)
  and for `analyze_registers` (explicit operands, sub-register folding, the
  implicit `%edx:%eax` on `idiv`/`cltd`, the SSE-divide exclusion, the
  two-operand `imul` no-false-`%edx` guard, zero-touch lines, out-of-range
  defensiveness, canonical ordering, and a regression check that the existing
  cost/mix fields are untouched). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the footprint reaches the API response (division touches `%edx`
  implicitly, `%ebp` dominates the totals, and the canonical ordering holds).
  These are marked `needs_gcc` and **skip automatically** if `gcc` with `-m32`
  support (the 32-bit multilib) is unavailable, so the suite still passes in a
  toolchain-less environment.
