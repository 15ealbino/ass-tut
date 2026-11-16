# Immediate-Operand Map

> Feature branch: `feat/immediate-operand-map`

## What it teaches

**Mission pillar 1 — make the Python → C → x86 mapping concrete** — and
**pillar 2 — train the reverse-engineering eye to read raw assembly.**

The sibling asm passes each read a different column of the operand table: the
[addressing-mode map](../addressing-modes/README.md) says what *mode* each
operand is — and already counts how many operands are `immediate` — the
[register footprint](../register-footprint/README.md) says *which registers* a
line touches, and the [stack frame map](../stack-frame-map/README.md) says
*which %ebp slots*. This pass reads the one thing the addressing map deliberately
leaves out: the **value** of each immediate — the actual `$5`, `$9`, `$.LC0` a
Python line's instructions encode.

Every operand of every mapped instruction that begins with `$` (an AT&T
immediate) is decoded into one of two kinds:

| Kind | Meaning | Example operand | Reported as |
|------|---------|-----------------|-------------|
| numeric | a literal integer constant | `$5`, `$-1`, `$0x20` | the value `5`, `-1`, `32` |
| symbolic | an address constant / label | `$.LC0`, `$main` | a *symbol ref* (no value) |

It reports two things:

- **Per Python line** — an `immediates` list of the **distinct numeric values**
  that line's asm encodes, sorted ascending, e.g. `[5, 9]`.
- **Program-wide** — an `ImmediateSummary`:
  - `value_totals` — each distinct numeric value (a string key, ordered by the
    underlying integer ascending so `"-1" < "10"`) → the number of operand
    occurrences of it, e.g. `{ "0": 2, "5": 1, "9": 1 }`.
  - `symbol_refs` — the count of symbolic `$`-operands program-wide (`$.LC0`
    string-pool pointers, `$symbol` address constants), which carry no number.
  - `distinct_values` — the number of distinct numeric values.

### Why this is its own lesson

- **It is the most direct Python → asm link there is.** Write `x = 5` and `$5`
  appears verbatim in the machine code; write `if n == 42` and `$42` appears.
  Where every other pass abstracts the asm into *categories* and *counts*, this
  one points at the literal you typed and shows it surviving, unchanged, into the
  instruction stream. That is the "this compiles down to that" moment made
  concrete — you can point at it.

- **The values you did *not* write are the real lesson.** A `for i in range(10)`
  loop does **not** encode `$10` as its bound:

  ```asm
  cmpl $9, -4(%ebp)     # i <= 9  — the compiler lowered `i < 10` to `i <= 9`
  jle  .L2
  ```

  The constant in the asm is `$9`, off-by-one from the `10` in your source,
  because `i < 10` is the same test as `i <= 9`. Seeing that gap is exactly the
  habit a reverse-engineer needs: the constants in a disassembly encode the
  program's real limits, but only *after* the compiler's transformations — the
  number on the page is rarely the number in the code.

- **A symbolic immediate is "this is an address, not a number."** A
  `print("hello")` line carries no numeric literal at all. Instead the string's
  address is a *symbolic* operand — a pointer into the read-only string pool.
  Depending on the toolchain's PIC default it shows up either as an immediate
  (`movl $.LC0, ...` / `pushl $.LC0`, counted in `symbol_refs`) or as a
  PIC-relative memory reference (`leal .LC0@GOTOFF(%ebx), %eax`, which the
  [addressing-mode map](../addressing-modes/README.md) classifies as a
  `displacement`). Learning to tell an address operand from a numeric one on
  sight is a day-one RE skill, and a magic constant you never wrote — a mask, a
  sentinel, a reciprocal — is the thread you pull on when reversing unfamiliar
  code.

## How a learner uses it

1. Write Python in the editor and compile (the default `transpile` pipeline).
2. Look at the **TRACE** legend bar along the bottom. Alongside the existing
   `COST::`, `MIX::`, `REGS::`, `MEM::`, `SENSE::`, and `ADDR::` chips, a new
   `IMM:: 5×2 · 7 · 9 · +1 sym` chip lists the literal values the whole program
   encodes (`value×occurrences`, then a `+N sym` tail for symbolic refs).
3. Hover any per-line chip: its tooltip now includes `imm: 5, 9` alongside the
   instruction count, cost, mix, registers, memory, and addressing modes.
4. Experiment with the off-by-one. Compile this:

   ```python
   total = 0
   for i in range(10):
       total = total + i
   ```

   The `IMM::` chip shows `$9`, **not** `$10` — the loop bound the compiler
   actually emitted. Change `range(10)` to `range(100)` and watch it become `$99`.
   Then add `n = 42` and see `$42` appear exactly on that line's tooltip.

## How it works technically

The compile pipeline already builds a `line_map` of
`py_line → { c_lines, asm_lines, color }` by parsing GCC `.loc` directives, and
the cost / mix / register / memory / branch / addressing passes annotate each
entry. The immediate-operand map is another **independent pass over the same
already-mapped assembly** — no extra compilation. It lives in its own module,
`backend/app/immediates.py`:

1. `parse_immediate_value(operand)` decodes one AT&T immediate's integer value,
   or returns `None`. It returns the value for a numeric immediate (`"$5"` → `5`,
   `"$-1"` → `-1`, `"$0x20"` → `32`) and `None` for anything else — an operand
   that is not an immediate, or a *symbolic* one whose body is not an integer
   (`"$.LC0"`, `"$main"`, `"$.LC0+4"`, a bare `"$"`). It **never raises**: a
   non-integer body falls through to `None` (counted as a symbol ref by the
   caller) rather than crashing. Hex is taken as written — `"$0xffffffff"` →
   `4294967295`, with **no** signed reinterpretation (see Scope).
2. `immediates_in_instruction(text)` splits one instruction's operand string on
   **top-level** commas (`_split_operands`, so a sibling `(%ebp,%eax,4)` group
   stays one operand) and returns `(numeric_values, symbol_refs)`; labels,
   directives, and operand-less instructions (`ret`, `cltd`, `leave`) contribute
   nothing.
3. `analyze_immediates(line_map, asm_lines)` runs alongside the other per-line
   passes, adds an `immediates` list (distinct numeric values, sorted ascending)
   to each `line_map` entry, and returns
   `{ "value_totals": { "<value>": count, … }, "symbol_refs": N, "distinct_values": N }`.
4. These fields are declared on `LineMapping` and a new `ImmediateSummary` in
   `backend/app/schemas.py` (defaulting to empty, so the pyghidra pipeline — which
   computes no per-line immediate map — still validates), mirrored in the
   frontend types in `frontend/src/api.ts`, and rendered by
   `frontend/src/pages/Editor.tsx` as the `IMM::` chip and the enriched per-line
   tooltips.

**Counting conventions (two, on purpose):** the per-line `immediates` list is
**deduplicated** (it answers "which values does this line encode"), while
`value_totals` counts **operand occurrences** (it answers "how often is each
value encoded overall"), matching the addressing-mode pass's operand-level
convention. So a line that names `$3` twice lists it once but contributes two to
`value_totals["3"]`. `distinct_values` always equals `len(value_totals)`. A
defensively-skipped out-of-range asm index contributes nothing.

## Scope

- **In scope:** per-line distinct numeric immediate values and a program-wide
  value/symbol summary in the API, and a minimal editor read-out (chip +
  tooltip), for the transpile pipeline.
- **Out of scope:**
  - **Signed reinterpretation of hex immediates.** `$0xffffffff` is reported as
    `4294967295`, the unsigned magnitude the assembler wrote, not `-1`. The
    transpiler emits negative literals as decimal (`$-1`) anyway, so this only
    affects hand-reading of hex masks.
  - **Which Python/C construct a value came from.** The map says `$9` is present;
    it does not tie it back to the `range(10)` that produced it (that lives in the
    per-line association, read by hovering the line).
  - **Symbolic immediate *identities*.** `symbol_refs` is a count; it does not
    list *which* symbols (`$.LC0` vs `$main`) or resolve a `$.LC0` back to its
    string contents.
  - **Floating-point / SSE immediates**, which gcc materialises from the
    `.rodata` constant pool via a memory load rather than a `$`-immediate, so they
    do not appear here.
  - The pyghidra pipeline; any change to the transpiler or C/asm generation, or to
    the existing per-line passes (this pass is orthogonal and purely additive).

## Running the tests

```bash
cd backend
pip install -r requirements.txt
SECRET_KEY=dev-secret pytest tests/test_immediate_operands.py
```

The test file has two layers:

- **Unit tests** for `parse_immediate_value` (decimal / hex / negative / the
  leading-zero `$08` edge / symbolic / non-immediate / empty), for
  `immediates_in_instruction` (the literal-store and loop-bound cases, a symbolic
  `$.LC0`, mixed operands, register/memory-only lines, operand-less instructions,
  labels and directives, and that a sibling scaled-index operand is kept intact),
  and for `analyze_immediates` (per-line distinct values, operand-occurrence
  totals, ordering by integer-not-string, out-of-range defensiveness, empty
  input, a no-instruction line, and the dedup-vs-occurrence-count invariant).
  These need no toolchain.
- **End-to-end `/compile` tests** that run the real transpiler + gcc pipeline and
  assert the signal reaches the API response: `immediate_summary` is present and
  well-formed, a `n = 42` literal surfaces as the value `42`, a `for i in
  range(10)` loop surfaces the off-by-one bound `9` (the headline lesson), a
  string literal adds no spurious numeric immediate, and `distinct_values` equals
  the number of `value_totals` keys. These are marked `needs_gcc` and **skip
  automatically** if `gcc` with `-m32` support is unavailable, so the suite still
  passes in a toolchain-less environment.
