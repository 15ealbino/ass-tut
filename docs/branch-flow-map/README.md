# Branch Flow Map

> Feature branch: `feat/branch-flow-map`

## What it teaches

**Mission pillars 1 and 2 — make the Python → C → assembly mapping clearer and
more concrete, AND train the eye to read control flow off a raw disassembly.**

Two shapes account for almost every branch a beginner sees in `-O0` x86 output:

* A Python `if` compiles to a **conditional forward jump** around the
  then-body — the "branch-around" pattern.
* A Python `for` / `while` compiles to a **conditional backward jump** that
  loops back to the test at the head of the loop — the "back-edge" pattern.

The branch flow map annotates each Python line's assembly with exactly which
branches it emits, whether each is conditional, and whether the target is
above (backward) or below (forward) the branch itself. Both shapes then read
right off your own code:

```
if x > 0:                #   cmpl $0, -4(%ebp)
    x = 1                #   jle  .L2       ← conditional FORWARD (skip then)
                         #   movl $1, ...
                         #   jmp  .L3       ← unconditional FORWARD (past else)
else:                    # .L2:
    x = 2                #   movl $2, ...
                         # .L3:

while i < 5:             # .L4:
    i += 1               #   cmpl $4, -8(%ebp)
                         #   jle  .L5       ← conditional BACKWARD (loop back)
```

Being able to say "backward = loop, forward-around = if" from the branches
alone is a day-one reverse-engineering skill and one of the fastest ways to
turn a wall of asm into structure. The map also teaches the wrong shapes —
a backward branch with no exit condition (infinite-loop bug), a forward
branch that skips a length check (a classic sanitiser bypass), or a chain
of `jmp` sleds (obfuscation / shellcode) — so a learner can flag suspicious
control flow at a glance instead of hunting for it instruction by
instruction.

### How it relates to the other analysis passes

The compile pipeline already runs several pure post-processing passes over
the same `line_map`. The branch flow map completes the control-flow picture
that the instruction mix only counts:

| Pass                | Answers                                     | Field |
|---------------------|---------------------------------------------|-------|
| cost analysis       | *how much* work (instruction count)         | `asm_count`, `flags` |
| instruction mix     | *what kind* of work (six categories)        | `category_counts` |
| register footprint  | *which registers* it uses                   | `registers` |
| stack frame map     | *which stack slots* it uses                 | `stack_slots` |
| memory traffic      | *loads vs stores* in the mem bucket         | `memory_counts` |
| **branch flow map** | *which branches* — mnemonic + direction     | **`branches`** |

The mix's `branch` category counts *how many* jump instructions a line has;
the branch flow map names each individual jump — its mnemonic, whether it is
conditional, and where it goes relative to itself.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Each Python line's `branches` field lists every branch instruction that
   line emitted, in occurrence order:

   ```jsonc
   [
     {"mnemonic": "jle", "conditional": true,  "direction": "forward",  "target": ".L2"},
     {"mnemonic": "jmp", "conditional": false, "direction": "forward",  "target": ".L3"}
   ]
   ```

3. The program-wide `branch_summary` gives:
   - `total` — number of branch instructions in the whole program;
   - `conditional` / `unconditional` — the mnemonic split (`jmp`/`jmpl` are
     unconditional; every `j*` conditional and every `loop*` are conditional);
   - `forward` / `backward` / `self_loop` — the direction split;
   - `external` — branches whose target label is not defined in the file
     (tail calls);
   - `unknown` — branches with an indirect target (`jmp *%eax`) or no operand.
4. Experiment. Add an `if` and watch `conditional` and `forward` both
   increment by one. Turn it into an `if/else` and watch the `jmp` past the
   else body add one to `unconditional` and one to `forward`. Add a `while`
   and watch `backward` appear for the first time — that's the loop
   back-edge. Nest a loop inside an `if` and see forward and backward
   branches land on the same Python line.

## How it works technically

No extra compilation. Like the cost/mix/register/stack/memory passes, the
branch flow map is a pure function of the existing `line_map`
(`py_line → {c_lines, asm_lines, color}`) and the filtered assembly text:

```
compile_python()
  └─ _parse_asm_line_map()   # existing: c_line → [asm_line], filtered asm text
  └─ build_line_map()        # existing: py_line → {c_lines, asm_lines, color}
  └─ analyze_cost()          # existing
  └─ analyze_registers()     # existing
  └─ analyze_stack()         # existing
  └─ analyze_memory_traffic()# existing
  └─ analyze_branches()      # NEW: annotate branches + build branch_summary
```

`analyze_branches(line_map, asm_lines)` (in `backend/app/compile.py`) works in
three simple steps:

1. **Label positions.** Walk `asm_lines` once and record every whole-line
   `<label>:` declaration to its 1-indexed display asm line number
   (`_label_positions`). An operand mention of the same symbol elsewhere
   (`jmp .L4`) is NOT a declaration — the trailing `:` distinguishes them.
   The map is global to the file, so `.LFB0`/`.LFE0` and dotted symbols like
   `__x86.get_pc_thunk.ax` are all findable.
2. **Per-line branch parse.** For each asm line a Python line maps to,
   `_parse_branch` extracts `(mnemonic, kind, target)` if the mnemonic is a
   branch. Classification (`classify_branch`):
   - `jmp` / `jmpl` → **unconditional**
   - every other `j*` (`je`, `jne`, `jl`, `jle`, `jg`, `jge`, `ja`, `jae`,
     `jb`, `jbe`, `js`, `jns`, `jz`, `jnz`, `jecxz`, …) → **conditional**
   - `loop` / `loope` / `loopne` (decrement-`%ecx`-and-branch) → **conditional**
3. **Direction.** `branch_direction(source_line, target, labels)` compares
   the branch's own display asm line to its target's:
   - target line **>** source → `"forward"` (skip past the then-body)
   - target line **<** source → `"backward"` (loop back-edge)
   - target line **==** source → `"self_loop"` (a branch to itself)
   - target label not in `labels` → `"external"` (a tail-call `jmp printf`)
   - no target text, or the target starts with `*` (`jmp *%eax`) →
     `"unknown"` (destination is computed at run time)

The per-line `branches` list is attached to each `line_map` entry (in
occurrence order — order matters when a line emits both a conditional and
an unconditional branch, as an `if/else` does). Program-wide, `branch_summary`
tallies:

- `total` — number of branch instructions overall;
- `conditional` + `unconditional` — the mnemonic split (must sum to `total`);
- `forward` + `backward` + `self_loop` + `external` + `unknown` — the
  direction split (must also sum to `total`).

Both fields are typed in `backend/app/schemas.py` (`Branch`,
`LineMapping.branches`, `BranchSummary`, `CompileResponse.branch_summary`) so
the frontend can consume them as they land.

### Why `call` and `ret` are not counted

`call` and `ret` are control flow, but they're already covered by the
instruction mix's `call` category and by the register footprint's implicit
`%esp` / `%eip` claims. Mixing them into the branch map would muddy the
forward-vs-backward reading the pass is built around: `call printf` is
"forward" in some trivial address sense but the useful lesson there is
*call overhead*, not control-flow shape. The branch map deliberately
scopes to intra-file `j*` / `loop*` — the ones an `if` / `for` / `while`
actually generates.

### Scope

- **In scope:** the `transpile` (AST → C → gcc `-m32 -O0`) pipeline. All
  intra-file branch instructions: `jmp`, every conditional `j*`, and the
  `loop*` family. Per-line entries in occurrence order and a program-wide
  summary.
- **Out of scope:**
  - `call` / `ret` — see above.
  - Extracting the *condition* a conditional branch tests (`jle .L2` after
    `cmp $0, x` really means "jump if x <= 0"). Reading the pair together is
    a natural next step; this pass only names the branch instruction.
  - Frontend UI. The `/compile` response carries `branches` and
    `branch_summary`; consuming them in the editor is a follow-up (the
    memory-traffic and stack-frame-map features shipped their backend passes
    the same way).
  - The `pyghidra` pipeline (returns `branch_summary: null` and an empty
    `line_map` — it computes no per-line control-flow map).

## How to run its tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=test-secret-key pytest tests/test_branch_flow_map.py -q
```

The test file has two layers:

- **Unit tests** (`classify_branch`, `_label_positions`, `_parse_branch`,
  `branch_direction`, `analyze_branches`) — pure, no toolchain required.
  They cover the mnemonic families (unconditional `jmp`/`jmpl`, every
  conditional `j*`, the `loop*` family, non-branches like `mov`/`call`/
  `ret`/`cmp`), label declaration vs operand mention, indirect targets
  (`*%eax`), the classic if/else and while-loop shapes, occurrence-order
  preservation across multiple branches on one line, the external / unknown
  paths, the out-of-range-index guard, the empty-input case, a regression
  check that the pass does not disturb the cost/mix annotations, and a
  consistency check that per-line entries and summary totals agree.
- **End-to-end tests** — POST real Python (`if`, `if/else`, `while`) to
  `/compile` and assert the branch signal reaches the response (a
  `branch_summary` is present, an `if` produces a conditional forward branch,
  a `while` produces a backward branch, and every emitted per-line entry
  carries the expected fields). These are guarded by a `gcc -m32`
  availability check and **skip automatically** where 32-bit multilib is
  not installed, so the suite stays green in a toolchain-less environment.

Run the full backend suite the same way:

```bash
SECRET_KEY=test-secret-key pytest -q
```
