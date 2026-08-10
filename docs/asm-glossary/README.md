# Assembly Instruction Glossary

> Feature branch: `feat/asm-glossary`

## What it teaches

**Mission pillar 1 — teach reverse engineering by making the Python → C →
assembly mapping clearer.** (Secondary: pillar 2 — knowing what `idiv`, `imul`,
and `call` *do* is the first step toward spotting expensive assembly.)

The [cost analysis](../asm-cost-analysis/README.md) tells you *how much* work a
Python line costs; the [instruction mix](../asm-instruction-mix/README.md) tells
you *what kind* of work it is. Both assume you can already read the mnemonics.
For a learner opening the ASM pane for the first time, that assumption doesn't
hold — `cltd`, `leal`, `movzbl`, and `idivl` are opaque. The glossary answers
the most elementary question first: **what does each of these mnemonics mean?**

For every **distinct** instruction mnemonic that actually appears in the
compiled assembly, the `/compile` response now carries one plain-English entry:

```json
{ "mnemonic": "idivl", "base": "idiv", "category": "compute",
  "description": "signed integer divide — very expensive (tens of CPU cycles)" }
```

- `mnemonic` — the exact opcode as emitted (e.g. `idivl`), so it matches what
  the learner sees in the ASM pane character-for-character.
- `base` — the canonical opcode family (`idiv`), so `movl`/`movzbl`/`movsbl`
  are recognisable as relatives of `mov`.
- `category` — the same six-bucket classification as the instruction-mix feature
  (`mem` / `compute` / `branch` / `call` / `stack` / `other`).
- `description` — a one-line, learner-facing meaning, with a cost hint on the
  expensive opcodes (`imul`, `idiv`, `div`).

Only distinct mnemonics are listed, so the glossary is a compact legend for the
program in front of you — typically a dozen or so entries — not a full x86
reference.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Next to the `COST::` and
   `MIX::` chips there is now a `GLOSSARY:: N OPS` chip, where `N` is the number
   of distinct mnemonics the program produced.
3. Hover the chip. Its tooltip lists every mnemonic and its meaning, ordered by
   category (all the memory moves, then the compute, then the branches, and so
   on) — a decoder ring for the ASM pane you're staring at.
4. Read the assembly with the glossary open. When the [mix](../asm-instruction-mix/README.md)
   chip says a line is *3 mem, 1 compute*, the glossary tells you the `mem`
   instructions are `movl` loads/stores and the `compute` one is an `addl` — the
   abstract category becomes concrete opcodes you can now name.

### Worked example

Compiling:

```python
x = 6
y = x * 7
```

produces assembly containing (among the frame setup) `pushl`, `movl`, `imull`,
and `ret`. The glossary for that response is:

```
mem      movl    copy data between registers, memory, and immediates (no arithmetic)
compute  imull   signed integer multiply (an order of magnitude costlier than a shift/add)
call     ret     return to the caller using the pushed return address
stack    pushl   push a value onto the stack (the stack grows downward)
```

The learner now knows the `imull` on the `y = x * 7` line (already flagged `×`
by the cost feature and bucketed `compute` by the mix) is a *signed multiply* —
and why it's singled out as expensive.

## How it works technically

The compile pipeline already produces the filtered display assembly
(`asm_lines`) and, in the same pass, annotates each Python line with
`asm_count` / `flags` / `category_counts` (see
`backend/app/compile.py::analyze_cost`). The glossary is a second, independent
scan of that **same** `asm_lines` — no additional compilation:

1. `build_asm_glossary(asm_lines)` (in `backend/app/asm_glossary.py`) walks the
   display assembly. Blank lines, `.`-prefixed directives, and label lines
   (ending in `:`) carry no mnemonic and are skipped. Each remaining line's
   first whitespace-separated token is lowercased into a mnemonic, and the
   **first** occurrence of each distinct mnemonic yields one entry.
2. The **description** comes from `_GLOSSARY_PREFIXES`, an ordered
   first-match-wins prefix table local to `asm_glossary.py`. One entry covers
   every size-suffixed variant — `"mov"` catches `movl`/`movw`/`movb`, `"j"`
   catches every remaining conditional jump. More specific prefixes are listed
   before the prefixes they start with (`movz`/`movs` before `mov`, `fldz`
   before `fld`, `jmp` before `j`, `leave` before `lea`), and a regression test
   (`test_no_glossary_prefix_is_shadowed_by_an_earlier_one`) proves none is dead.
   An unrecognised mnemonic is never dropped: it keeps its own name as `base`
   and gets a generic "consult an x86 reference" description.
3. The **category** is *not* re-derived. `build_asm_glossary` imports
   `classify_category` from `backend/app/compile.py` (a lazy, function-local
   import, because `compile` imports `build_asm_glossary` at module load — the
   lazy import breaks that cycle) and uses it verbatim. This makes
   `classify_category` the single source of truth, so the glossary and the
   instruction-mix chip can never disagree about which bucket an opcode is in.
4. Entries are returned sorted by category display order
   (`_CATEGORY_ORDER` from `compile.py`), then mnemonic, so the response is
   deterministic.
5. `compile_python` adds the resulting list to its response dict under
   `asm_glossary`. The field is declared as `GlossaryEntry` /
   `CompileResponse.asm_glossary` in `backend/app/schemas.py` (defaulting to an
   empty list, so the pyghidra pipeline — which returns no glossary — still
   validates), mirrored in `frontend/src/api.ts`, and rendered as the
   `GLOSSARY::` chip in `frontend/src/pages/Editor.tsx`.

**Invariant:** every entry's `category` equals
`classify_category(entry["mnemonic"])`, and the `mnemonic` values are unique
across the list.

## Scope

- **In scope:** a plain-English glossary of the distinct mnemonics the program
  already emitted, with per-opcode family, category, and description, surfaced
  in the API and a compact editor read-out.
- **Out of scope:** any change to the transpiler or C/asm generation; operand or
  addressing-mode decoding (the glossary explains opcodes, not their arguments);
  per-line glossary wiring (per-line meaning is already served by the mix and
  cost flags); the pyghidra pipeline, whose Ghidra disassembly is not annotated;
  a full x86 instruction reference.

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_asm_glossary.py
```

The test file has two layers:

- **Unit tests** for `build_asm_glossary` (distinct-mnemonic dedup;
  label/directive/blank exclusion; category delegation to `classify_category`;
  the unknown-mnemonic fallback; deterministic ordering; the `leave`-vs-`lea`
  shadowing hazard; and a table-wide guard that no prefix is shadowed by an
  earlier one). These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline
  and assert the glossary reaches the API response (valid, distinct entries; an
  `imul` entry in `compute` for a multiply; and that every entry's category
  matches `classify_category` end to end). These are marked `needs_gcc` and
  **skip automatically** if `gcc` with `-m32` support (the 32-bit multilib) is
  unavailable, so the suite still passes in a toolchain-less environment.
