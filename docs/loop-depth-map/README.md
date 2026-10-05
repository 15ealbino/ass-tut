# Loop-Depth Map

> Feature branch: `feat/loop-depth-map`

## What it teaches

**Mission pillars 1 and 2 — make the Python → assembly mapping concrete, AND
train the eye to spot the *real* hotspot in inefficient assembly.**

Every other per-line pass describes a *single* execution of a Python line: the
cost pass counts its instructions, the cycle pass weights them by latency, the
mix / register / stack passes describe their shape. None of them answer the
question that actually decides a program's cost: **how many times does this line
run?**

That number is dominated by loop nesting. An instruction at loop depth 2 runs
`outer × inner` times. The single costliest `idiv` in a program is almost never
the one on a straight-line setup line — it is the cheap-looking one buried two
loops deep. The loop-depth map recovers that nesting straight from the assembly,
the way a reverse-engineer does: by reading the **back-edges**.

```
total = 0                 #   movl $0, -4(%ebp)        ← depth 0 (setup)
for i in range(3):        # .L_outer:  cmpl … ; jle .  ← depth 1
    for j in range(3):    # .L_inner:  cmpl … ; jle .  ← depth 2
        acc = acc // j    #   … idivl …                ← depth 2  ← HOTSPOT
```

The `idiv` on the last line is ~20 cycles *per iteration*, and it runs
`3 × 3 = 9` times. Reading `cycle_estimate: 20` next to `loop_depth: 2` on the
same line is how a learner finds the true hotspot — and the fix (hoist the
divide out of the inner loop) follows directly from the depth.

### How a loop reads off the assembly

A Python `for` / `while` compiles at `gcc -O0` to exactly one **backward
branch** — a jump whose target label sits *above* the branch, looping control
flow back to the top of the loop body:

```
    jmp .L2            # forward, to the test  (NOT a loop edge)
.L3:                   # loop-body head        ← span start
    <body>             #                        ← depth 1
.L2:                   # loop test
    cmpl $4, -8(%ebp)
    jle .L3            # BACKWARD branch        ← span end  →  loop span (.L3 … jle)
```

An `if` / `else`, by contrast, compiles only to **forward** branches (the
branch-around), so it defines no loop. The span from a back-edge's target down
to the back-edge itself is one loop body; the number of such spans covering an
instruction is its loop-nesting depth. Recovering structure from back-edges is a
day-one reverse-engineering skill, and this pass automates it for every line.

### How it relates to the other analysis passes

| Pass                 | Answers                                          | Field            |
|----------------------|--------------------------------------------------|------------------|
| cost analysis        | *how much* work, once (instruction count)        | `asm_count`, `flags` |
| cycle-cost estimate  | *how expensive* one pass is (latency weight)     | `cycle_estimate` |
| instruction mix      | *what kind* of work it is                        | `category_counts` |
| branch flow map      | *which branches* — mnemonic + direction          | `branches`       |
| **loop-depth map**   | *how many times* the line runs (nesting depth)   | **`loop_depth`** |

The branch-flow map already names each backward branch; the loop-depth map turns
those back-edges into structure and attaches the **run-count multiplier** the
cost and cycle estimates omit. Cost × depth is the complete picture.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Each Python line's `loop_depth` says how many loops its assembly runs inside:
   `0` is straight-line code, `1` is inside one loop, `2` is inside two nested
   loops (so the line runs `outer × inner` times).
3. The program-wide `loop_summary` gives:
   - `loop_count` — number of loop back-edges detected (one per source
     `for` / `while`);
   - `max_depth` — the deepest nesting anywhere in the program;
   - `hotspots` — every Python line at depth ≥ 1 (the lines that run
     repeatedly), ranked deepest-first.
4. Experiment. Add a `for` loop and watch `loop_count` and `max_depth` both go
   to `1` and the body line's `loop_depth` become `1`. Nest a second loop inside
   it and watch the inner body reach `loop_depth: 2` while the outer header stays
   at `1`. Pair it with the cost pass: put an `acc // i` inside the inner loop
   and see a `div` flag land on a line that is also `loop_depth: 2` — the real
   hotspot, named by two passes agreeing.

## How it works technically

No extra compilation. Like the cost / mix / register / stack / branch passes,
the loop-depth map is a pure function of the existing `line_map`
(`py_line → {c_lines, asm_lines, color}`) and the filtered assembly text:

```
compile_python()
  └─ _parse_asm_line_map()   # existing: c_line → [asm_line], filtered asm text
  └─ build_line_map()        # existing: py_line → {c_lines, asm_lines, color}
  └─ analyze_cost()          # existing
  └─ analyze_branches()      # existing: names each backward branch
  └─ analyze_loops()         # NEW: back-edges → spans → per-line loop_depth
```

`analyze_loops(line_map, asm_lines)` (in `backend/app/loops.py`) works in three
steps:

1. **Label positions.** Walk `asm_lines` once and record every whole-line
   `<label>:` declaration to its 1-indexed display asm line (`_label_positions`,
   the same shape the branch-flow map uses). An operand mention of the same
   symbol (`jmp .L3`) is not a declaration — the trailing `:` distinguishes them.
2. **Loop spans.** For every branch instruction (`branch_target` recognises
   `jmp` / `jmpl`, every conditional `j*`, and the `loop*` family — `call` / `ret`
   are deliberately excluded as call overhead, not loop structure), look up its
   target label's line. If the target is declared **strictly above** the branch,
   it is a back-edge, and `loop_spans` records the inclusive span
   `(target_line, branch_line)`. Forward branches (if/else) and external targets
   (tail calls whose label is not in the file) are excluded.
3. **Depth.** `depth_at(asm_line, spans)` counts the spans covering a line. Each
   `line_map` entry's `loop_depth` is the **maximum** depth over the asm lines it
   maps to — a loop-header line shares its body's depth because the loop's
   condition test re-runs every iteration. `max_depth` is computed over the whole
   asm stream (not just mapped lines), so it is correct even where the innermost
   instruction carries no `.loc`.

Both the per-line `loop_depth` and the `LoopSummary`
(`loop_count` / `max_depth` / `hotspots`) are typed in `backend/app/schemas.py`
(`LineMapping.loop_depth`, `LoopHotspot`, `LoopSummary`,
`CompileResponse.loop_summary`) so the frontend can consume them as they land.

### Scope

- **In scope:** the `transpile` (AST → C → gcc `-m32 -O0`) pipeline. Loop
  nesting recovered from intra-file backward branches (`jmp` / conditional `j*`
  / `loop*`), a per-line `loop_depth`, and a program-wide summary. The depth is
  exact for the reducible, singly-back-edged loops this transpiler's
  `for` / `while` emit.
- **Out of scope:**
  - A precise *iteration count* (`range(5)` runs 5 times). Depth is the nesting
    multiplier, not the trip count — reading the loop bound off the `cmp` is a
    natural next step.
  - Irreducible / multi-entry loops and `goto`-style control flow: the
    transpiler never emits them, and the back-edge reading degrades gracefully
    (it never raises and never counts a forward branch as a loop) rather than
    pretending to analyse them.
  - `call` / `ret` recursion — a different kind of repetition, already visible
    via the instruction mix's `call` category.
  - Frontend UI. The `/compile` response carries `loop_depth` and
    `loop_summary`; consuming them in the editor is a follow-up, exactly as the
    branch-flow, memory-traffic, and stack-frame passes shipped their backends.
  - The `pyghidra` pipeline (returns `loop_summary: null` and `loop_depth: 0` —
    it computes no per-line loop map).

## How to run its tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=test-secret-key pytest tests/test_loop_depth_map.py -q
```

The test file has two layers:

- **Unit tests** (`branch_target`, `loop_spans`, `depth_at`, `analyze_loops`) —
  pure, no toolchain required. They run against synthetic asm snippets (a single
  loop and two nested loops) and cover: branch-target extraction vs non-branches
  (`mov` / `call` / `ret` / `cmp` / labels / indirect `*%eax` / operand-less),
  back-edge detection, exclusion of forward branches and external targets, the
  `max`-over-mapped-lines rule for loop headers, nested-depth attribution,
  the no-loops zero case, `max_depth` being independent of the line map, the
  out-of-range-index guard, a regression check that the pass does not disturb
  prior annotations, and a consistency check between per-line depths and the
  summary.
- **End-to-end tests** — POST real Python (straight-line, a single `for`, two
  nested `for`s, and a divide inside a loop) to `/compile` and assert the loop
  signal reaches the response (`loop_summary` present, correct `loop_count` /
  `max_depth`, body lines at the expected depth, hotspots ranked deepest-first),
  grounded against the branch-flow map's backward-branch count and the cost
  pass's `div` flag. These are guarded by a `gcc -m32` availability check and
  **skip automatically** where 32-bit multilib is not installed, so the suite
  stays green in a toolchain-less environment.

Run the full backend suite the same way:

```bash
SECRET_KEY=test-secret-key pytest -q
```
