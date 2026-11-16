# EFLAGS Producer/Consumer Map

> Feature branch: `feat/eflags-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** — and
**pillar 2 — train the reverse-engineering eye to read raw assembly.**

The sibling asm passes each name one part of a Python line's compiled control
flow: the [instruction mix](../asm-instruction-mix/README.md) lumps every jump
into a single `branch` bucket, the [branch-sense map](../asm-branch-map/README.md)
classifies a conditional jump as **signed vs unsigned**, and the
[branch-flow map](../branch-flow-map/README.md) classifies it as **forward vs
backward**. All three describe the *jump itself*. None of them answers the
question a reverse-engineer must answer to understand any comparison in a
disassembly: **for a conditional jump, where were the flags it tests set?**

x86 conditional control flow runs through the **EFLAGS** register, and EFLAGS
appears in **no operand**. Consider `if a < b:` at `-O0`:

```asm
movl  -8(%ebp), %eax
cmpl  -4(%ebp), %eax     # sets EFLAGS (SF/ZF/OF/CF) from (a - b)
jge   .L2                # reads EFLAGS — but names neither a, b, nor the cmp
```

The `jge` depends on the `cmpl` three bytes earlier, yet **nothing in the jump's
text says so**. The data dependency is entirely implicit — exactly like the
implicit `%edx:%eax` the [register footprint](../register-footprint/README.md)
pass surfaces for integer division. This pass makes that hidden channel
countable by sorting every instruction a Python line maps to into one of three
**flag roles** (and leaving flag-neutral instructions uncounted, the way the
branch-sense pass ignores non-jumps):

| Role | Meaning | Example mnemonics |
|------|---------|-------------------|
| `set-cmp` | a **dedicated** flag setter — exists only to set EFLAGS for a branch | `cmp`, `test` |
| `set-alu` | arithmetic / logic / shift that sets EFLAGS as a **side effect** of computing a value | `add`, `sub`, `and`, `or`, `xor`, `inc`, `dec`, `neg`, `imul`, `idiv`, `sal`, `shr`, … |
| `use` | a flag **consumer** — reads EFLAGS | `jl`/`jge`/`je`/… (conditional jumps), `setcc`, `cmov`, `adc`, `sbb` |

It reports two things:

- **Per Python line** — a `flag_effect_counts` map with the nonzero roles in
  display order, e.g. `{ "set-cmp": 1, "use": 1 }`.
- **Program-wide** — a `flag_totals` map summing every line, e.g.
  `{ "set-cmp": 2, "set-alu": 5, "use": 2 }`.

### Why this is its own lesson

- **The invisible operand (pillar 1 + reverse-engineering skill).** A
  conditional jump's most important input — the flags — is named nowhere on the
  line. Reading *backward* from a `jcc` to the instruction that set its flags is
  a day-one RE task precisely because the compiler leaves the link implicit.
  Seeing a Python `if`/`while`/`for` lower to exactly one `set-cmp` feeding one
  `use` turns "the comparison becomes a jump" from a slogan into a
  producer→consumer pair you can point at.
- **The flag-clobber hazard (pillar 2).** `set-alu` counts every instruction
  that writes EFLAGS *as a side effect* — an `add`, an `and`, a shift — whether
  or not anything reads the result. That matters because an arithmetic
  instruction landing **between a `cmp` and its `jcc`** silently overwrites the
  flags the branch depends on: the compare no longer decides the branch. gcc at
  `-O0` keeps the `cmp` adjacent to its `jcc`, so a healthy program here shows
  `set-cmp` and `use` *in step*; the `set-alu` tally is the population of
  flag-writers that a reordering (a hand-written asm edit, a buggy peephole, an
  attacker-supplied gadget chain) could interpose. This map trains the eye to
  notice that risk.
- **Two famous non-setters.** `mov` and `lea` do **not** touch EFLAGS, and
  neither does `not` — classic traps when reading a disassembly, because they
  *look* like "work." They are deliberately classified as flag-neutral (role
  `None`), so they never inflate `set-alu`. (The `lea`-doesn't-set-flags gotcha
  is the same one the [memory-traffic](../asm-memory-traffic/README.md) pass
  leans on, where `lea` is "address math, not a memory access.")

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Alongside the existing
   `COST::`, `MIX::`, `REGS::`, `MEM::`, `SENSE::`, and `ADDR::` chips, a new
   `EFLAGS:: N cmp · N alu · N use` chip shows the program-wide flag-role split.
   (Labelled `EFLAGS::`, not `FLAGS::`, to stay distinct from the cost pass's
   per-line `flags`/"expensive" markers.)
3. Hover any per-line chip: its tooltip now includes `eflags: …` alongside the
   instruction count, cost, mix, registers, memory, addressing, and branch
   senses.
4. Experiment. A straight-line program has **no** `use` role at all — nothing
   branches:

   ```python
   x = 5
   y = x + 7
   ```

   Now add a comparison and watch a `set-cmp` producer and a `use` consumer
   appear together on the loop/`if` line:

   ```python
   n = 10
   t = 0
   while t < n:
       t = t + 1
   ```

   The `while t < n:` line gains `set-cmp` (the `cmpl`) and `use` (the `jl`); the
   `t = t + 1` line is pure `set-alu` (an `addl` whose flags nothing reads).

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost / mix / register / memory / addressing / branch passes annotate each
entry. The EFLAGS map is another **independent pass over the same already-mapped
assembly** — no extra compilation. It lives in its own module,
`backend/app/flags.py`:

1. `classify_flag_effect(mnemonic)` sorts one lowercased mnemonic (the first
   whitespace-separated token) into `set-cmp` / `set-alu` / `use`, or `None` for
   a flag-neutral instruction. Matching is by prefix (so `cmpl` folds to `cmp`,
   `jge` to the conditional-jump family), with a few ordered guards:
   - **Jumps first.** A conditional jump is a `use`; the unconditional `jmp`
     reads nothing, and the `jecxz`/`jcxz` family tests `%ecx` rather than the
     flags — both are `None`.
   - **SSE suffix guard.** Scalar/packed FP arithmetic (`addsd`, `mulss`,
     `cmpsd`) does not write EFLAGS, so a mnemonic ending in `ss`/`sd`/`ps`/`pd`
     is `None` *before* the integer prefix tables run — otherwise `add`/`cmp`
     would misfire. (The fixed `-m32` `-O0` build emits x87 `f*` ops for this
     transpiler's doubles anyway, which are likewise left uncounted.)
   - **Consumers before producers.** `setcc`, `cmov`, and the carry-chain
     `adc`/`sbb` are `use`. They are checked before the producer tables so that
     `adc`/`sbb` — which also *write* flags — are reported by the role that
     matters when reading control flow (they consume a carry a prior op set), and
     so `cmov*` is never mistaken for `cmp`.
   - **Producers.** `cmp`/`test` → `set-cmp`; the arithmetic/logic/shift family →
     `set-alu`. `mov`, `lea`, and `not` are **absent** from every table, so they
     stay `None`.
2. `analyze_flag_effects(line_map, asm_lines)` runs alongside the other per-line
   passes, adds a `flag_effect_counts` map to each `line_map` entry (nonzero
   roles only, in the fixed display order `set-cmp < set-alu < use`), and returns
   `{ "flag_totals": { role: count, … } }`.
3. These fields are declared on `LineMapping` and a new `FlagSummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline —
   which computes no per-line flag map — still validates), mirrored in the
   frontend types in `frontend/src/api.ts`, and rendered by
   `frontend/src/pages/Editor.tsx` as the `EFLAGS::` chip and the enriched
   per-line tooltips.

**Counting convention:** counts are of **instructions**, each contributing its
single role, so a line's per-role counts sum to the number of its instructions
that touch EFLAGS (never more than its total instruction count), and summing
every line's counts reproduces `flag_totals`. A defensively-skipped out-of-range
asm index contributes nothing.

## Scope

- **In scope:** per-line flag-role counts and a program-wide total in the API,
  and a minimal editor read-out (chip + tooltip), for the transpile pipeline.
- **Out of scope:** *which* individual flags (ZF/SF/OF/CF/PF/AF) each instruction
  reads or writes — only the coarse producer/consumer role is reported; pairing a
  specific consumer with the specific producer that set its flags (no cross-line
  flag-dependency chain is built — the roles are counted, not linked);
  flag-clobber *detection* between a compare and its jump (the `-O0` output keeps
  them adjacent, so the map surfaces the *population* of flag-writers, not a proven
  reorder bug); the x87 status word / SSE compare flags (the fixed build does not
  emit them, and they are left uncounted conservatively); the pyghidra pipeline;
  any change to the transpiler or C/asm generation, or to the existing per-line
  passes (this pass is orthogonal and purely additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_flags.py
```

The test file has two layers:

- **Unit tests** for `classify_flag_effect` (every role plus the edge cases: the
  `adc`/`sbb` vs `add`/`sub` opposites, `cmov` vs `cmp`, the `jmp`/`jecxz`
  non-uses, the `lea`/`not`/`mov` flag-neutral traps, the sign-extends
  `cltd`/`cdq`, and the x87/SSE FP forms) and `analyze_flag_effects` (per-line
  counts, display ordering, out-of-range defensiveness, empty input, a
  flag-neutral line, a no-instruction line, and the counts-sum-to-totals
  invariant). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response: `flag_summary` is present, every
  line carries a `flag_effect_counts` map, a straight-line program has **no**
  `use` role, a program with a `while`/`if` **does** produce both `set-cmp` and
  `use`, and the program totals equal the sum of the per-line counts. These are
  marked `needs_gcc` and **skip automatically** if `gcc` with `-m32` support is
  unavailable, so the suite still passes in a toolchain-less environment.
