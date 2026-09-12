# Branch-Condition Map (signed vs unsigned)

> Feature branch: `feat/asm-branch-map`

## What it teaches

**Mission pillar 2 — train engineers to spot vulnerable assembly and the
Python/C bug behind it.** (With a helping of pillar 1: it makes control flow
legible in the disassembly.)

The [instruction mix](../asm-instruction-mix/README.md) sorts every jump into a
single `branch` bucket, and the [glossary](../asm-glossary/README.md) describes a
conditional jump generically as "taken only when the flags satisfy the
condition". Neither answers the one question that matters most when you read a
comparison in a disassembly: **is the branch signed or unsigned?**

x86 has **two parallel families** of conditional jumps that read the *same*
`cmp`, differing only in how they interpret the flags:

| sense       | mnemonics                       | interprets operands as |
| ----------- | ------------------------------- | ---------------------- |
| **signed**  | `jl` `jle` `jg` `jge` `js` `jns` | `int` (SF/OF ordering) |
| **unsigned**| `jb` `jbe` `ja` `jae` `jc` `jnc` | `unsigned` (CF ordering)|
| **equality**| `je`/`jz` `jne`/`jnz`           | sense-neutral          |
| unconditional | `jmp`                         | always taken           |

It reports two things:

- **Per Python line** — a `branch_sense_counts` map with only the nonzero senses, e.g.
  `{ "signed": 1, "unconditional": 1 }`.
- **Program-wide** — a `branch_totals` map, same senses summed across every line
  (empty when the program has no jumps).

### Why this is its own lesson

Picking the wrong jump family is a **textbook vulnerability**. Consider a bounds
check `if (len < size)` where `len` is signed and attacker-controlled. Compiled
with a **signed** branch (`jl`), a negative `len` passes the check — then gets
used as a huge `size_t` in a copy. Compiled with an **unsigned** branch (`jb`),
the same bytes read as a giant positive number and *fail* the check. Same
compare, opposite safety outcome, and the *only* visible difference in the
assembly is one letter of the mnemonic.

This transpiler emits **all-`int` C**, so gcc emits the **signed** family. That
is exactly what makes the feature a good teacher: the expected, correct output is
"all signed", so an **unsigned branch is an anomaly** — the day one shows up, a
comparison was treated as unsigned somewhere, and that is precisely the smell a
reverse engineer must learn to catch. Seeing `2 signed` next to a Python
`if a < b` makes the normal case concrete and trains the eye for the exception.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom, after the existing chips
   (`COST::`, `MIX::`, `REGS::`, `MEM::`):
   - A new `BRANCH:: N signed · N eq …` chip shows the program's jumps by sense.
   - Hover it for the full signed-vs-unsigned explanation.
   - Hover any per-line chip: its tooltip now includes `branch: N signed …`
     alongside the instruction count, mix, registers, memory, and flags.
3. Experiment:
   - `if a < b:` → a `cmp` + a **signed** ordering jump.
   - `if a == b:` → a `cmp` + an **equality** jump (`je`/`jne`).
   - `for i in range(n):` / `while i < n:` → the loop's back-edge is a **signed**
     jump (the `int` counter compare), plus an `unconditional` jump into the
     condition test.
   - Straight-line arithmetic (`c = a + b`) → **no** conditional branches at all.

### Worked example

```python
total = 0
for i in range(10):
    total += i
```

The `for` line compiles (at `gcc -O0 -m32`) to roughly:

```asm
        jmp     .L2             # unconditional: jump to the condition test
.L3:
        ...                     # loop body: total += i
.L2:
        cmpl    $9, -8(%ebp)    # compare i against the bound (signed int)
        jle     .L3             # SIGNED jump-if-less-or-equal back into the body
```

The `for` line's `branch_sense_counts` is `{ "signed": 1, "unconditional": 1 }`. The
`jle` is signed because `i` is an `int`; if you ever saw `jbe` here instead, the
loop counter was being compared as `unsigned` — the classic off-by-one /
wrap-around bug source.

## How it works technically

The pass lives in `backend/app/compile.py`, alongside the cost, mix, register,
stack, and memory passes, and runs over the **same** filtered display assembly
they all consume (the `.loc`-driven `py_line → [asm_line]` map built in
`_parse_asm_line_map` / `build_line_map`).

- **`classify_branch_sense(mnemonic)`** maps a lowercased mnemonic to exactly one of
  `"signed"`, `"unsigned"`, `"equality"`, `"unconditional"`, `"other"`
  (overflow/parity jumps), or `None` for any non-jump instruction. Matching is
  **exact-set**, not prefix-based like the mix/glossary tables: jump mnemonics
  are short and their prefixes overlap (`j` prefixes them all; `jn` prefixes both
  `jne` and `jnb`), so a prefix scan would mis-sort them. The signed, unsigned,
  and equality sets are asserted **disjoint** by a unit test — blurring signed
  and unsigned is the very bug the feature exists to expose.
- **`analyze_branch_senses(line_map, asm_lines)`** walks each line's mapped asm lines,
  classifies each instruction's first token, and accumulates per-line
  `branch_sense_counts` and a program-wide `branch_totals`. Both drop zero senses and
  order keys by a stable `_BRANCH_SENSE_ORDER`, mirroring the zero-omitting
  instruction-mix maps. It mutates `line_map` in place and does not touch any
  field written by the earlier passes.

The result is surfaced through:

- `backend/app/schemas.py` — `LineMapping.branch_sense_counts`, a `BranchSenseSummary`
  model, and `CompileResponse.branch_sense_summary` (`Optional`, `None` for the
  pyghidra pipeline, which has no per-line `.loc` map).
- `frontend/src/api.ts` — the mirrored `branch_sense_counts` / `BranchSenseSummary` /
  `branch_sense_summary` types.
- `frontend/src/pages/Editor.tsx` — `formatBranches()` plus the `BRANCH::`
  legend chip and per-line tooltip annotation.

A conditional jump still counts toward `asm_count` and the `branch`
instruction-mix bucket. This pass **refines** that bucket by direction of sense;
it does not replace it (a regression test pins that invariant).

## Scope

**In scope:** classifying every jump the display asm contains by sense, per line
and program-wide.

**Out of scope:**

- Pairing each jump with the specific `cmp`/`test` that set its flags, or
  decoding the compared operands. That is cross-instruction and error-prone; the
  sense alone carries the signed/unsigned lesson.
- The `loop`/`loope`/`jecxz` family (gcc `-O0` never emits it for this
  transpiler's code; classified `other` if ever seen, not specially handled).
- Per-line branch analysis for the **pyghidra** pipeline — like every other
  per-line pass, it has no `.loc` line map, so `branch_sense_summary` is `None` there.

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=test-secret pytest tests/test_branch_map.py -q
```

The suite has two layers, mirroring `test_memory_traffic.py`:

- **Unit tests** for `classify_branch_sense` and `analyze_branch_senses` run everywhere —
  they need no compiler.
- **End-to-end `/compile` tests** exercise the real transpiler + gcc pipeline and
  assert the branch signal reaches the API response (a loop yields signed and no
  unsigned branches; an `if ==` yields an equality branch; straight-line code
  yields none). They **skip automatically** when `gcc` with `-m32` support is
  unavailable, so the suite still passes in a toolchain-less environment.
