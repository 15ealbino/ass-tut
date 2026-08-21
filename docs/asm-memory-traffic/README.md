# Memory Traffic (loads vs stores)

> Feature branch: `feat/asm-memory-traffic`

## What it teaches

**Mission pillar 2 — train engineers to spot bad/inefficient assembly and the
Python behind it.**

The [instruction mix](../asm-instruction-mix/README.md) sorts every instruction
into one bucket and lumps all data movement — every `mov`, in either direction —
into a single `mem` category. Memory traffic splits that bucket by **direction**:
how many memory **reads (loads)** and **writes (stores)** each Python line
performs.

It reports two things:

- **Per Python line** — a `memory_counts` map with the nonzero of
  `{ "loads", "stores" }`, e.g. `{ "loads": 1, "stores": 1 }`.
- **Program-wide** — a `memory_totals` map, `{ "loads": N, "stores": N }`
  (both keys always present).

### Why this is its own lesson

At `gcc -O0` every local variable lives in a stack slot, not a register. So even
the most trivial line becomes a **read-modify-write round-trip through memory**.
The canonical example — `x += 1` — compiles to:

```asm
movl -4(%ebp), %eax     # load  x  from its stack slot
addl $1, %eax           # compute in a register
movl %eax, -4(%ebp)     # store x  back to its stack slot
```

One load and one store just to add one. The `mem` instruction-mix bucket already
shows "2 mem" here, but it can't tell you the two moves go in **opposite
directions** — that this is a round-trip, not two reads. Memory traffic makes the
direction explicit ("1 load · 1 store"), and the program-wide totals quantify how
much of your program is pure stack shuffling: work that an optimising build
(`-O2`, which keeps `x` in a register) would erase entirely. Learning to see that
load/store overhead — and to recognise it as an artefact of unoptimised codegen
rather than something inherent to the algorithm — is exactly the eye pillar 2
trains.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - `COST:: N INSTR` — total instruction count (cost feature).
   - `MIX:: mem N · compute N …` — program-wide instruction mix (mix feature).
   - `REGS:: %eax N …` — register footprint (registers feature).
   - A new `MEM:: N ld · N st` chip shows the program's total memory reads and
     writes.
   - Hover any per-line chip: its tooltip now includes `mem: N ld · N st`
     alongside the instruction count, mix, registers, and expensive-op flags.
3. Experiment. Write `x = 0` then `x += 1` and watch both a load and a store
   appear. Add a loop that repeatedly reads and writes a counter and watch the
   totals climb — every iteration re-loads and re-stores the same value because
   `-O0` never promotes it to a register.

### Worked example

Compiling:

```python
x = 0
x += 1
```

- `x = 0` stores the constant into `x`'s stack slot → `{ "stores": 1 }`.
- `x += 1` loads `x`, adds, stores it back → `{ "loads": 1, "stores": 1 }`.

Program-wide: `memory_totals = { "loads": 1, "stores": 2 }`. The single increment
alone is responsible for one of every kind of memory access — the round-trip made
visible.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost/mix/register passes annotate each entry. Memory traffic is another
independent pass over the **same** already-mapped assembly — no extra
compilation:

1. `memory_accesses(text)` (in `backend/app/compile.py`) returns `(loads, stores)`
   for one assembly instruction line. A memory operand in AT&T syntax always
   carries a parenthesised base/index register (`-4(%ebp)`, `(%eax)`,
   `sym@GOTOFF(%ebx)`, `(%eax,%ecx,4)`), matched by `_MEM_OPERAND_RE`;
   immediates (`$5`), bare registers (`%eax`), and code labels (`.L2`) carry no
   such form. Operands are split on **top-level** commas (`_split_operands`) so a
   comma inside `(%eax,%ecx,4)` never splits the operand.
2. Direction is decided by operand **position** (AT&T: the last operand is the
   destination), refined by a small mnemonic table for the cases where position
   alone misleads:
   - `lea*` computes an address and never touches memory → always `(0, 0)`.
   - `mov*` overwrites its destination (pure **store**); every other mnemonic
     that writes a memory destination is **read-modify-write** — a memory
     destination counts as both a load and a store (`addl %eax, -4(%ebp)`).
   - `cmp`/`test` only **read** their destination (they set flags and discard the
     result), so a memory "destination" there is a **load** (`cmpl $0, -4(%ebp)`).
   - single-operand `pop`/x87-store (`fst*`/`fist*`/`fbstp`)/RMW
     (`inc`/`dec`/`neg`/`not`/shifts) write their operand; every other
     single-operand memory access (`push`, `idiv`, `fld`, a memory branch target)
     reads it.
3. `analyze_memory_traffic(line_map, asm_lines)` runs after `analyze_cost` /
   `analyze_registers`, adds a `memory_counts` map to each `line_map` entry
   (nonzero keys only, mirroring the instruction mix), and returns
   `{ "memory_totals": { "loads": N, "stores": N } }`.
4. These fields are declared on `LineMapping` and a new `MemorySummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline — which
   computes no per-line traffic — still validates), mirrored in the frontend
   types in `frontend/src/api.ts`, and rendered by `frontend/src/pages/Editor.tsx`
   as the `MEM::` chip and the enriched per-line tooltips.

**Invariant:** each instruction touches memory at most twice — one load plus one
store, the read-modify-write case — so a line's `loads + stores` never exceeds
`2 × asm_count`. A defensively-skipped out-of-range asm index contributes nothing.

## Scope

- **In scope:** per-line load/store counts and a program-wide load/store total in
  the API, and a minimal editor read-out (chip + tooltip), for the transpile
  pipeline.
- **Out of scope:** distinguishing stack-slot vs global vs heap addresses (all
  counted uniformly as memory); the width of each access (byte vs word vs dword);
  bare-symbol direct memory operands with no parentheses (gcc's `-m32` PIC output
  routes globals through a parenthesised GOT base, so they do not occur for this
  transpiler's output); cache/latency modelling or cycle-accurate timing; the
  pyghidra pipeline; any change to the transpiler or C/asm generation, or to the
  existing cost/mix/register passes (memory traffic is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_memory_traffic.py
```

The test file has two layers:

- **Unit tests** for `memory_accesses` (the load/store direction of every
  instruction shape: pure load, pure store, immediate-to-memory store,
  memory-source arithmetic, read-modify-write to memory, single-operand
  push/pop/idiv, `cmp`/`test` reads, the `lea` no-access rule, x87 `fld`/`fst`,
  indexed addressing, and register-only / label / directive lines) and for
  `analyze_memory_traffic` (the round-trip, per-line zero-omission, load-only /
  store-only lines, cross-line totals, out-of-range defensiveness, empty input,
  and a regression check that the existing cost/mix fields are untouched). These
  need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the traffic reaches the API response (`memory_summary` is present with
  both keys, `x += 1` produces both load and store traffic, and per-line counts
  stay bounded by the instruction count). These are marked `needs_gcc` and **skip
  automatically** if `gcc` with `-m32` support is unavailable, so the suite still
  passes in a toolchain-less environment.
