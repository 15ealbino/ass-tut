"""
Immediate-operand map — the literal constants each Python line's assembly carries.

The sibling asm passes each read a different column of the operand table: the
[addressing-mode map](addressing.py) says what *mode* each operand is (and already
counts how many operands are `immediate`), the register footprint says *which
registers* a line touches, the stack frame map says *which %ebp slots*. This pass
reads the one thing the addressing map deliberately leaves out — the *value* of
each immediate: the actual `$5`, `$9`, `$.LC0` a line's instructions encode.

Every operand of every mapped instruction that begins with `$` (an AT&T immediate)
is decoded:

    numeric    a literal integer constant        `$5`, `$-1`, `$0x20`  → 5, -1, 32
    symbolic   an address constant / label        `$.LC0`, `$main`      → a symbol ref

The lessons this teaches (mission pillars 1 and 2):
  * Pillar 1 (make the mapping concrete): the single most direct Python → asm
    link there is. Write `x = 5` and `$5` appears in the machine code; write
    `if n == 42` and `$42` appears. Seeing your own literal reappear verbatim in
    the assembly makes "this compiles down to that" something you can *point at*,
    not just believe.
  * Pillar 1 + reverse-engineering skill: the values that AREN'T the ones you
    typed are the real lesson. `for i in range(10)` does not emit `$10` — it emits
    `$9`, because `i < 10` is lowered to the `i <= 9` test `cmpl $9`. The loop
    bound you wrote is off-by-one from the constant in the asm, and seeing that
    gap is exactly the habit a reverse-engineer needs: the constants in a
    disassembly encode the program's limits, but only after the compiler's
    transformations.
  * Pillar 2 (spot the magic number): an unexpected immediate is a tell. A
    `print("...")` line carries no numeric literal at all — instead a *symbolic*
    immediate (`$.LC0`, a pointer into the read-only string pool), which is how
    you learn to recognise "this operand is an address, not a number" on sight.
    And a magic constant you never wrote appearing on a line (a mask, a reciprocal,
    a sentinel) is the thread you pull on when reversing unfamiliar code.

Decoding is purely syntactic on the AT&T operand text and never raises: an
operand that begins with `$` but does not parse as an integer (a label, a
symbol, a symbol+offset, a malformed `$`) is counted as a *symbolic* reference
rather than dropped, so no immediate is ever silently lost. The integer value is
reported exactly as the assembler wrote it — `$0xffffffff` reads as 4294967295,
not -1; no signed reinterpretation is applied (see the feature README's Scope).
"""
from typing import Dict, List, Tuple


def parse_immediate_value(operand: str) -> int | None:
    """Decode a single AT&T immediate operand's integer value, or ``None``.

    ``operand`` is one already-split operand string (stripped defensively here).
    Returns the integer value for a numeric immediate — ``"$5"`` → ``5``,
    ``"$-1"`` → ``-1``, ``"$0x20"`` → ``32`` — and ``None`` for anything else:
    an operand that is not an immediate (does not begin with ``$``), or a
    *symbolic* immediate whose body is not an integer (``"$.LC0"``, ``"$main"``,
    ``"$.LC0+4"``, a bare ``"$"``).

    The value is taken exactly as written: a hex immediate decodes to its
    unsigned magnitude (``"$0xffffffff"`` → ``4294967295``), with no signed
    reinterpretation. Never raises.
    """
    op = operand.strip()
    if not op.startswith("$"):
        return None
    body = op[1:]
    if not body:
        return None  # a bare "$" — malformed; treated as symbolic by the caller
    # Base 0 handles decimal, 0x-hex, and the leading sign; the base-10 fallback
    # catches the (gcc-unlikely) leading-zero decimal `$08` that base 0 rejects.
    try:
        return int(body, 0)
    except ValueError:
        try:
            return int(body, 10)
        except ValueError:
            return None


def _is_immediate(operand: str) -> bool:
    """True if an operand is an AT&T immediate (begins with ``$``)."""
    return operand.strip().startswith("$")


def _split_operands(operand_str: str) -> List[str]:
    """Split an AT&T operand string on top-level commas, keeping the commas that
    sit inside an addressing-mode parenthesis together (so ``(%eax,%ecx,4)``
    stays one operand rather than three).

    Mirrors the splitter used by the addressing-mode and memory-traffic passes;
    kept local so this module stays self-contained like the other per-line
    analysers. An immediate never contains parentheses, but a sibling operand on
    the same instruction can (``movl $.LC0, -4(%ebp,%eax,4)``), so the splitter
    must still respect them to isolate the immediate cleanly.
    """
    operands: List[str] = []
    depth = 0
    current: List[str] = []
    for ch in operand_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == "," and depth == 0:
            operands.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        operands.append(tail)
    return operands


def immediates_in_instruction(text: str) -> Tuple[List[int], int]:
    """Return ``(numeric_values, symbol_refs)`` for one assembly instruction line.

    ``text`` is a raw display-asm line. ``numeric_values`` is the list of decoded
    integer immediates in source order (with repeats — an instruction is free to
    name the same value twice); ``symbol_refs`` is the count of ``$``-operands
    that are symbolic (a label / address constant like ``$.LC0``) rather than a
    number.

    Labels (``.L2:``), directives (``.cfi_*``, ``.string "hi"``) and operand-less
    instructions (``ret``, ``cltd``, ``leave``) carry no immediate operand and
    return ``([], 0)`` — only real instruction operands are decoded.
    """
    stripped = text.strip()
    if not stripped or stripped.startswith(".") or stripped.endswith(":"):
        return ([], 0)
    parts = stripped.split(None, 1)
    if len(parts) < 2:
        return ([], 0)  # operand-less instruction (ret, cltd, leave, nop, …)
    values: List[int] = []
    symbol_refs = 0
    for op in _split_operands(parts[1]):
        if not _is_immediate(op):
            continue
        v = parse_immediate_value(op)
        if v is None:
            symbol_refs += 1
        else:
            values.append(v)
    return (values, symbol_refs)


def _ordered_value_totals(totals: Dict[int, int]) -> Dict[str, int]:
    """Render an int→count map as a str-keyed map ordered by numeric value
    ascending (JSON object keys are strings; the ordering is by the underlying
    integer so ``-1`` precedes ``0`` precedes ``10``, not lexicographically)."""
    return {str(v): totals[v] for v in sorted(totals)}


def analyze_immediates(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with an ``immediates`` list and return a
    program-wide summary. Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    Per line, ``immediates`` is the sorted list of *distinct* numeric immediate
    values that line's assembly references (a "what constants does this line
    encode" list, mirroring the distinct-set convention of ``registers`` /
    ``stack_slots``). The program-wide summary is::

        {
          "value_totals":    {"<value>": instruction_operand_count, ...},  # by value asc
          "symbol_refs":     <count of symbolic $-operands program-wide>,
          "distinct_values": <number of distinct numeric immediate values>,
        }

    ``value_totals`` counts OPERAND occurrences (an immediate named twice across
    two instructions counts twice), matching the addressing-mode pass's
    operand-level convention; ``symbol_refs`` likewise counts symbolic
    ``$``-operands. The per-line ``immediates`` list is deduplicated while the
    totals are not, so the two answer different questions ("which values appear
    here" vs. "how often is each value encoded overall").
    """
    totals: Dict[int, int] = {}
    symbol_refs = 0
    for mapping in line_map.values():
        line_values: set = set()
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                values, syms = immediates_in_instruction(asm_lines[asm_no - 1])
                symbol_refs += syms
                for v in values:
                    line_values.add(v)
                    totals[v] = totals.get(v, 0) + 1
        mapping["immediates"] = sorted(line_values)

    return {
        "value_totals": _ordered_value_totals(totals),
        "symbol_refs": symbol_refs,
        "distinct_values": len(totals),
    }
