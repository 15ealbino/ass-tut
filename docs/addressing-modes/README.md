# Addressing-Mode Map

> Feature branch: `feat/addressing-modes`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** — and
**pillar 2 — train the reverse-engineering eye to read raw assembly.**

The sibling asm passes each answer a neighbouring question about a Python line's
compiled code: the [instruction mix](../asm-instruction-mix/README.md) says *what
kind* of work it does, [memory traffic](../asm-memory-traffic/README.md) says how
many **loads/stores** it performs, the
[register footprint](../register-footprint/README.md) says *which registers* it
touches, and the [stack frame map](../stack-frame-map/README.md) says *which %ebp
slots*. This pass answers the orthogonal question a reverse-engineer asks the
instant they read an operand: **what addressing mode is this?**

Every operand of every instruction a Python line maps to is sorted into exactly
one of five addressing modes:

| Mode | Meaning | Example operand |
|------|---------|-----------------|
| `immediate` | a literal value / address constant | `$5`, `$.LC0` |
| `register` | register-direct | `%eax`, `%st(0)` |
| `displacement` | base register + displacement — **a stack local** | `-4(%ebp)`, `(%eax)` |
| `indexed` | base + **scaled index** — **an array element** | `-24(%ebp,%eax,4)` |
| `direct` | a bare symbol / code target | `.L2`, `helper` |

It reports two things:

- **Per Python line** — an `addressing_counts` map with the nonzero modes in
  display order, e.g. `{ "immediate": 1, "displacement": 2 }`.
- **Program-wide** — an `addressing_totals` map summing every line, e.g.
  `{ "immediate": 4, "register": 9, "displacement": 12, "indexed": 2 }`.

### Why this is its own lesson

Two modes carry the outsized teaching signal:

- **`displacement` dominates at `-O0`.** Because every local variable is spilled
  to the stack, nearly every operand is a `-N(%ebp)` slot. Seeing that one mode
  swamp the totals makes the abstract "everything lives on the stack" story into
  something you can *count*.
- **`indexed` is the fingerprint of array access.** When you write `xs[i]` in
  Python, it compiles to a **scaled base+index** operand — the index register,
  multiplied by the element size, added to the frame base:

  ```asm
  movl -40(%ebp,%eax,4), %edx   #  edx = xs[i]   (i in %eax, 4-byte ints)
  ```

  That `,4` scale is unmistakable once you know it: it *is* "walk an array of
  4-byte elements." Recognising it at a glance is a day-one reverse-engineering
  skill, and its **absence of a neighbouring bounds check** is exactly how
  out-of-range array reads hide in a disassembly (pillar 2). No plain Python
  arithmetic ever produces this mode — only indexing does — so it appears on
  precisely the lines that touch an array.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Alongside the existing
   `COST::`, `MIX::`, `REGS::`, `MEM::`, and `SENSE::` chips, a new
   `ADDR:: N imm · N reg · N disp · N idx …` chip shows the program-wide
   addressing-mode split.
3. Hover any per-line chip: its tooltip now includes `addr: …` alongside the
   instruction count, cost, mix, registers, memory, and branch senses.
4. Experiment. A plain program (`x = 5`, `y = x + 7`) is almost entirely
   `displacement` and `immediate` — no `indexed` at all. Now add a list and index
   it in a loop and watch an `indexed` entry appear on exactly the line that
   reads `xs[i]`:

   ```python
   xs = [10, 20, 30]
   s = 0
   for i in range(3):
       s = s + xs[i]
   ```

   The `s = s + xs[i]` line gains an `indexed` operand; the plain lines never do.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost / mix / register / memory / branch passes annotate each entry. The
addressing-mode map is another **independent pass over the same already-mapped
assembly** — no extra compilation. It lives in its own module,
`backend/app/addressing.py`:

1. `classify_operand(operand)` sorts one AT&T operand into its mode, and is
   **total** — anything that is not an immediate, a register, or a parenthesised
   memory reference falls into `direct`, so no operand is ever dropped:
   - `immediate` — begins with `$`.
   - A **memory operand** carries a `(...%...)` base/index group (matched by
     `_MEM_GROUP_RE`). It is `indexed` when that group contains a comma (a
     base+index[,scale] form — the array fingerprint) and `displacement`
     otherwise.
   - `register` — begins with `%` and is not a memory operand (covers the x87
     `%st(0)`, whose parentheses hold no `%`).
   - `direct` — everything else (bare symbols, code targets, indirect `*%eax`).
2. `operand_modes(text)` splits one instruction's operand string on **top-level**
   commas (`_split_operands`, so `(%ebp,%eax,4)` stays a single operand) and
   classifies each; labels, directives, and operand-less instructions (`ret`,
   `cltd`, `leave`) contribute nothing.
3. `analyze_addressing(line_map, asm_lines)` runs alongside the other per-line
   passes, adds an `addressing_counts` map to each `line_map` entry (nonzero
   modes only, in the fixed display order
   `immediate < register < displacement < indexed < direct`), and returns
   `{ "addressing_totals": { mode: count, … } }`.
4. These fields are declared on `LineMapping` and a new `AddressingSummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline — which
   computes no per-line addressing map — still validates), mirrored in the
   frontend types in `frontend/src/api.ts`, and rendered by
   `frontend/src/pages/Editor.tsx` as the `ADDR::` chip and the enriched per-line
   tooltips.

**Counting convention:** counts are of **operands**, not instructions — a
`movl -4(%ebp), -8(%ebp)`-style two-memory instruction would contribute two
`displacement` operands — so a line's per-mode counts always sum to its total
operand count, and summing every line's counts reproduces `addressing_totals`. A
defensively-skipped out-of-range asm index contributes nothing.

## Scope

- **In scope:** per-line addressing-mode counts and a program-wide total in the
  API, and a minimal editor read-out (chip + tooltip), for the transpile
  pipeline.
- **Out of scope:** the width of each access (byte vs word vs dword); resolving
  *which* variable a slot or symbol names (the
  [stack frame map](../stack-frame-map/README.md) covers slot identity); the
  scale factor or displacement value of an indexed operand (only the mode is
  reported); RIP-relative / segment-override modes (gcc's `-m32` output for this
  transpiler emits neither); cache or latency modelling; the pyghidra pipeline;
  any change to the transpiler or C/asm generation, or to the existing per-line
  passes (this pass is orthogonal and purely additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_addressing.py
```

The test file has two layers:

- **Unit tests** for `classify_operand` (every mode plus edge cases: the x87
  `%st(0)` register, `sym@GOTOFF(%ebx)`, the indexed `.L4(,%eax,4)`, an indirect
  `*%eax`, and the empty operand), `operand_modes` (operand order, operand-less
  instructions, labels, directives, and that a scaled-index operand is kept
  intact rather than split on its internal commas), and `analyze_addressing`
  (per-line counts, display ordering, out-of-range defensiveness, empty input, a
  no-instruction line, and the operands-sum-to-totals invariant). These need no
  toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response: `addressing_summary` is present,
  every line carries an `addressing_counts` map, a plain program is
  `displacement`-heavy with **no** `indexed` mode, indexing an array (`xs[i]`)
  **does** produce the `indexed` mode, and the program totals equal the sum of the
  per-line counts. These are marked `needs_gcc` and **skip automatically** if
  `gcc` with `-m32` support is unavailable, so the suite still passes in a
  toolchain-less environment.
