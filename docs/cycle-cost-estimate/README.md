# Cycle-Cost Estimate

> Feature branch: `feat/cycle-cost-estimate`

## What it teaches

**Mission pillar 2 — train engineers to spot bad/inefficient assembly and the
Python behind it.**

The [cost analysis](../asm-cost-analysis/README.md) feature counts *how many*
x86 instructions each Python line compiled to. But a raw instruction count
treats every instruction as equal, and they are not: a single `idiv` costs tens
of CPU cycles, while a `mov` or an `add` is roughly one. A Python line that
compiles to three instructions — one of them a divide — can be **costlier** than
a line that compiles to eight moves.

Cycle-cost estimate answers the sharper question the instruction count only
gestures at: **which Python lines actually cost the most?** It assigns each
mapped instruction an approximate, latency-oriented weight and sums them per
line.

It reports two things:

- **Per Python line** — a `cycle_estimate` integer: the summed approximate cycle
  weight of the instructions that line maps to.
- **Program-wide** — a `cycle_summary` of
  `{ "total_cycles": N, "hotspots": [{ "py_line", "cycles" }, …] }`, the hotspots
  ranked costliest-first — the cycle-weighted counterpart to the instruction-count
  hotspots.

### Why this is its own lesson

The headline: **instruction count is not cost.** The two rankings can *invert*.
Compile this:

```python
def f(a, b):
    c = a + b
    return a // b
```

| Python line   | asm instr | cycle est | note                    |
|---------------|-----------|-----------|-------------------------|
| `def f(a, b)` | 5         | 8         | prologue + a `call`     |
| `c = a + b`   | 4         | 4         | all one-cycle staples   |
| `return a // b` | **3**   | **22**    | `cltd` + `idivl` (÷20)  |

By instruction **count**, the divide line is the *shortest* — it ranks **last**.
By cycle **cost**, it is by far the *most expensive* — it ranks **first**. A
learner reading only the instruction count would look right past the one line
that dominates the program's actual work. Seeing `≈22 cyc` on a three-instruction
line, next to `≈4 cyc` on a longer one, makes the divide's dominance concrete and
trains the eye to weight what it sees — exactly the judgement pillar 2 is about.

Comparing the program-wide `CYCLES::` total against the `COST::` instruction
total tells the complementary story: a large gap means a few genuinely expensive
operations (divides, multiplies, calls) dominate; a small gap means the program
is mostly cheap stack shuffling that an optimising build would keep in registers.

> **These are coarse, relative teaching estimates — not cycle-accurate figures.**
> Real latencies vary by microarchitecture, operand location, and pipelining. The
> goal is to rank lines by rough order-of-magnitude cost, not to predict
> wall-clock time.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom:
   - `COST:: N INSTR` — total instruction count (cost feature).
   - `MIX:: mem N · compute N …` — program-wide instruction mix (mix feature).
   - `REGS:: %eax N …` — register footprint (registers feature).
   - `MEM:: N ld · N st` — memory traffic (memory feature).
   - A new `CYCLES:: ≈N cyc` chip shows the program's total estimated cost.
   - Hover any per-line chip: its tooltip now includes `cost: ≈N cyc` alongside
     the instruction count, mix, registers, memory, and expensive-op flags.
3. Experiment. Start with `x = a + b`, note the estimate equals the instruction
   count (all cheap staples). Change it to `x = a * b` and watch the estimate
   pull ahead of the count (the `imul` weighs 3). Change it to `x = a // b` and
   watch it jump (the `idiv` weighs 20). The gap between the `CYCLES::` and
   `COST::` chips is the whole lesson in one glance.

## The weight model

Each instruction's weight is chosen by its mnemonic family (matched by prefix, so
every size-suffixed variant — `idivl`, `imull`, `faddp` — is covered by one
entry). The magnitudes are intentionally round and encode a **teaching order**,
not measured latencies:

| Weight | Instruction family                         | Why                                   |
|-------:|--------------------------------------------|---------------------------------------|
| 20     | `idiv` / `div` (incl. SSE `divsd`)         | integer divide — dominant cost at -O0 |
| 18     | `fdiv`, `fsqrt`                            | x87 divide / square root              |
| 5      | `fmul`, `fadd`, `fsub`                     | x87 floating-point ALU                |
| 4      | `call`                                     | pipeline disruption + stack traffic   |
| 3      | `imul` / `mul`, `ret`, `loop`, x87 compare | multiply and lighter overhead         |
| 2      | `jmp` and conditional jumps, x87 load/store| control flow / x87 stack moves        |
| 1      | everything else                            | the one-cycle staples (`mov`, `add`, `lea`, `push`, `cmp`, shifts, …) |

The default weight of `1` is the load-bearing assumption: every cheap staple
folds into it, so only the notably expensive families need an explicit entry, and
no instruction is ever dropped from the sum.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost / mix / register / memory passes annotate each entry. Cycle-cost is
another independent pass over the **same** already-mapped assembly — no extra
compilation:

1. `cycle_weight(mnemonic)` (in `backend/app/cycle_cost.py`) returns the
   approximate relative weight for one lowercased mnemonic by first-match prefix
   lookup against `_WEIGHT_PREFIXES`, falling back to `DEFAULT_WEIGHT` (1). Like
   `classify_category`, it is **total**: an unrecognised or empty mnemonic still
   returns a weight, so every instruction contributes.
2. `analyze_cycles(line_map, asm_lines)` runs after the other per-line passes,
   sums each mapped instruction's weight into a `cycle_estimate` on the
   `line_map` entry, and returns
   `{ "total_cycles": N, "hotspots": [...] }`. Hotspots are ranked by estimated
   cost descending, tie-broken by `py_line` for determinism, and include only
   lines that produced instructions. An out-of-range asm index is skipped
   defensively (never crashes, never counted).
3. These fields are declared on `LineMapping` (`cycle_estimate`, default 0) and a
   new `CycleSummary` in `backend/app/schemas.py` (default `None`, so the pyghidra
   pipeline — which computes no per-line cost — still validates), mirrored in the
   frontend types in `frontend/src/api.ts`, and rendered by
   `frontend/src/pages/Editor.tsx` as the `CYCLES::` chip and the enriched
   per-line tooltips.

**Invariant:** the program-wide `total_cycles` equals the sum of every line's
`cycle_estimate` — the pass sums each mapped instruction exactly once, into both
its line and the total. A cheap line (only weight-1 staples) has
`cycle_estimate == asm_count`; a line with a multiply, divide, call, or branch
has `cycle_estimate > asm_count` — that gap *is* the amplification the feature
surfaces.

## Scope

- **In scope:** a per-line `cycle_estimate` and a program-wide `total_cycles` +
  cost-ranked `hotspots` in the API, and a minimal editor read-out (chip +
  tooltip), for the transpile pipeline.
- **Out of scope:** cycle-accurate or microarchitecture-specific timing (the
  weights are coarse relative estimates by design); modelling operand location,
  cache misses, memory latency, or instruction-level parallelism / pipelining;
  distinguishing throughput from latency; the pyghidra pipeline; any change to the
  transpiler or C/asm generation, or to the existing cost / mix / register /
  memory passes (cycle-cost is orthogonal and additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_cycle_cost.py
```

The test file has two layers:

- **Unit tests** for `cycle_weight` (the weight of every family and its
  size-suffixed variants, the `jmp`-before-`j` ordering, and that all cheap
  staples fall through to the default) and for `analyze_cycles` (per-line summing
  and the program total, the **count-vs-cost ranking inversion** that is the
  feature's headline lesson, deterministic hotspot tie-breaking, out-of-range
  defensiveness, empty input, and a zero-instruction line). These need no
  toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response (`cycle_summary` is present, the
  total equals the sum of per-line estimates, a divide line's estimate exceeds its
  instruction count by a wide margin, and a divide-free program shows no
  amplification). These are marked `needs_gcc` and **skip automatically** if `gcc`
  with `-m32` support is unavailable, so the suite still passes in a toolchain-less
  environment.
