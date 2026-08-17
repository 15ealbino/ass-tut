# Stack Frame Map

> Feature branch: `feat/stack-frame-map`

## What it teaches

**Mission pillar 1 — make the Python → C → assembly mapping clearer and more
concrete** — plus a core **reverse-engineering skill**: reading a stack frame off
a disassembly.

At `gcc -O0` there is no register allocation to speak of: almost every value is
spilled to a **stack slot** addressed relative to the frame pointer `%ebp`. The
stack frame map surfaces, for each Python line, the exact slots its assembly
touches — so the abstract claim "every variable lives on the stack" becomes
something you can read straight off your own code:

```
def f(a, b):        # a → 8(%ebp), b → 12(%ebp)   (incoming args)
    x = a + b       # x → -4(%ebp)                 (a local)
    return x
```

The System V i386 calling convention gcc uses here is legible in the offsets
themselves:

```
        higher addresses
   ┌──────────────────────┐
   │  12(%ebp)  arg b     │   POSITIVE offsets  → incoming arguments
   │   8(%ebp)  arg a     │      (pushed by the caller)
   │   4(%ebp)  ret addr  │
   │   0(%ebp)  saved ebp │ ← %ebp points here
   │  -4(%ebp)  local x   │   NEGATIVE offsets  → this function's own locals
   └──────────────────────┘
        lower addresses
```

Being able to say "negative = my locals, positive = my caller's arguments" from
the offsets alone is exactly the muscle a beginner needs when they first stare at
a disassembly in Ghidra or gdb.

### How it relates to the other analysis passes

The compile pipeline already runs several pure post-processing passes over the
same `line_map`. The frame map is the **memory-side complement** to the register
footprint:

| Pass                | Answers                              | Field |
|---------------------|--------------------------------------|-------|
| cost analysis       | *how much* work (instruction count)  | `asm_count`, `flags` |
| instruction mix     | *what kind* of work                  | `category_counts` |
| register footprint  | *which registers* it uses            | `registers` |
| **stack frame map** | *which stack slots* it uses          | **`stack_slots`** |

The mix's `mem` category counts *how many* memory instructions a line has; the
frame map says *which slots* they hit — reconstructing the frame layout instead
of just counting traffic.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Each Python line's `stack_slots` lists the distinct `%ebp`-relative slots that
   line reads or writes, ordered by offset (locals first, then args):
   `["-4(%ebp)", "8(%ebp)", "12(%ebp)"]`.
3. The program-wide `stack_summary` gives:
   - `slot_totals` — every slot mapped to the number of instructions that touch
     it (spill-heavy `-O0` code re-reads the same slot again and again — watch a
     single local rack up a high count),
   - `frame_slots` — how many distinct slots the whole program uses,
   - `locals_bytes` — a lower-bound estimate of the local-variable region.
4. Experiment. Add a parameter and watch a new positive-offset slot appear. Add a
   local and watch `locals_bytes` grow. See the *same* local slot get touched
   many times because `-O0` never keeps it in a register.

## How it works technically

No extra compilation. Like the cost/mix/register passes, the frame map is a pure
function of the existing `line_map` (`py_line → {c_lines, asm_lines, color}`) and
the filtered assembly text:

```
compile_python()
  └─ _parse_asm_line_map()   # existing: c_line → [asm_line], filtered asm text
  └─ build_line_map()        # existing: py_line → {c_lines, asm_lines, color}
  └─ analyze_cost()          # existing
  └─ analyze_registers()     # existing
  └─ analyze_stack()         # NEW: annotate stack_slots + build stack_summary
```

`analyze_stack(line_map, asm_lines)` (in `backend/app/compile.py`):

- For each assembly line a Python line maps to, it finds every memory operand
  based on `%ebp` with `_STACK_SLOT_RE` and extracts the signed displacement:
  - `-4(%ebp)` → `-4`, `8(%ebp)` → `8`, `(%ebp)` → `0`,
  - the indexed array form `-24(%ebp,%eax,4)` → `-24` (the base slot; the
    per-element address is computed at run time and is not a fixed slot),
  - hex displacements (`0x10(%ebp)`) are parsed defensively.
- Each displacement is rendered back to its disassembly-style label via
  `canonical_slot` (`-4` → `"-4(%ebp)"`, `0` → `"(%ebp)"`), so what you read in
  the map matches what you read in the ASM pane.
- Per line: `stack_slots` is the distinct set of slot labels, ordered by numeric
  offset ascending (locals `-N` first, then args `+N`).
- Program-wide: `slot_totals` counts, per slot, the instructions referencing it
  (a slot named twice in one instruction counts once); `frame_slots` is the
  number of distinct slots; `locals_bytes` is the magnitude of the most-negative
  offset seen.

The per-line `stack_slots` is attached to each `line_map` entry and
`stack_summary` is added to the `/compile` response. Both are typed in
`backend/app/schemas.py` (`LineMapping.stack_slots`, `StackSummary`) and mirrored
in `frontend/src/api.ts`.

### A note on `locals_bytes`

`locals_bytes` is a **lower bound**, not the exact frame size. gcc's prologue
`sub $N, %esp` (which actually reserves the frame) carries no `.loc` directive and
is therefore not in `line_map`; the compiler may also reserve extra bytes for
16-byte stack alignment. Read it as "your locals reach at least this deep,"
computed from the deepest slot any of your Python lines actually touches.

### Scope

- **In scope:** the `transpile` (AST → C → gcc `-m32 -O0`) pipeline.
  `%ebp`-relative frame slots — the function's locals (negative offsets) and its
  incoming arguments (positive offsets).
- **Out of scope:**
  - `%esp`-relative slots — outgoing-argument staging for the *next* call
    (`movl %eax, (%esp)`). That is a distinct concept from the current frame and
    is deliberately excluded so the map reads as one coherent frame.
  - Correlating a slot back to its Python/C variable *name* (the map shows the
    slot, not which named variable lives there).
  - The `pyghidra` pipeline (returns `stack_summary: null` and an empty
    `line_map` — it computes no per-line frame map).
  - Exact frame size / alignment padding (see the `locals_bytes` note above).

## How to run its tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=test-secret-key pytest tests/test_stack_frame_map.py -q
```

The test file has two layers:

- **Unit tests** (`canonical_slot`, `_stack_offsets_in_instruction`,
  `analyze_stack`) — pure, no toolchain required. They cover slot-label
  rendering, operand parsing (simple, zero-displacement, indexed, hex, `%esp`
  rejection, register-only lines), per-line slot sets, offset ordering,
  per-slot instruction counts, the `locals_bytes` lower bound, the
  out-of-range-index guard, the empty-input case, and a regression check that the
  pass does not disturb the cost/mix annotations.
- **End-to-end tests** — POST real Python to `/compile` and assert the frame
  signal reaches the response (a `stack_summary` is present, args land at
  positive offsets and locals at negative offsets, slots come back ordered by
  offset). These are guarded by a `gcc -m32` availability check and **skip
  automatically** where 32-bit multilib is not installed, so the suite stays
  green in a toolchain-less environment.

Run the full backend suite the same way:

```bash
SECRET_KEY=test-secret-key pytest -q
```
