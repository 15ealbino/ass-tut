"""
Immediate-constant map — the literal numbers baked into each Python line's asm.

The sibling asm passes each read one axis of a line's assembly: the instruction
mix says what KIND of work it does, the addressing map says what FORM its
operands take, the register footprint says WHICH registers it touches, and the
stack frame map says WHICH %ebp slots. This pass reads the axis a
reverse-engineer reaches for the moment a constant catches their eye: *which
literal values are embedded in the instruction stream itself* — the immediate
(``$``-prefixed) operands.

Where the addressing map only *counts* immediate operands ("3 imm"), this pass
recovers the actual VALUES: ``$42`` → ``42``, ``$0x1f`` → ``31``, ``$-1`` →
``-1``. The per-line list and the program-wide tally let a learner read the
program's constants straight off the disassembly.

The lessons this teaches (mission pillars 1 and 2):
  * Pillar 1 (make the mapping concrete): a Python literal lands in the asm as an
    immediate you can point at. Write ``x = 42`` and ``$42`` appears in the
    ``movl`` for that line; the mapping stops being abstract when you can find
    your own number in the instruction stream.
  * Pillar 2 + reverse-engineering skill: *constant recovery* is a day-one RE
    task — embedded magic numbers (sizes, masks, sentinels, table bounds) are
    often the fastest way to understand what a stripped function does. And the
    immediates split into two tellable groups: the ones a learner wrote, and the
    ones the COMPILER synthesised. Even at -O0 gcc strength-reduces a
    power-of-two multiply/divide, so ``x * 8`` emits a shift by ``$3`` and
    ``n % 8`` a mask ``$7`` — constants that are nowhere in the Python source.
    Learning to tell "my 8" (gone) from "the compiler's 3 and 7" (present) is
    exactly the codegen-fingerprint reading that makes a disassembly legible,
    and it is the same reflex that flags a suspicious bound or sentinel in
    hostile code.

Classification is purely syntactic on the AT&T operand text. Only NUMERIC
immediates are recovered; a symbolic / address immediate (``$.LC0``, ``$main``)
is deliberately left out — it is an address constant, not a value a learner can
reason about, and under this app's ``-m32`` PIC build addresses are loaded
through the GOT rather than as ``$`` immediates anyway (see the feature README's
"out of scope"). The pass is total in the sense the others are: an operand that
is not a parseable numeric immediate simply contributes nothing, so a line with
no literals gets an empty list rather than being skipped.
"""
import re
from typing import Dict, List, Optional, Set

# A numeric immediate operand in AT&T syntax: a leading ``$`` then an optional
# sign and either a ``0x``-prefixed hex run or a decimal run. Anchored end-to-end
# so a symbolic immediate (``$.LC0``, ``$main``, ``$sym+4``) does NOT match — it
# is an address constant, not a value, and is intentionally not recovered.
_IMM_NUM_RE = re.compile(r"^\$(?P<val>-?(?:0[xX][0-9a-fA-F]+|\d+))$")


def parse_immediate(operand: str) -> Optional[int]:
    """Return the signed integer value of a numeric immediate operand, or ``None``.

    ``operand`` is a single already-split AT&T operand string (stripped here
    defensively). Returns the decimal value of a ``$``-prefixed numeric literal:

    * ``"$42"`` → ``42``; ``"$0"`` → ``0``; ``"$-1"`` → ``-1``.
    * ``"$0x1f"`` → ``31``; ``"$-0x10"`` → ``-16`` (hex, case-insensitive).

    Any operand that is not a numeric immediate returns ``None``: a symbolic /
    address immediate (``"$.LC0"``, ``"$main"``), a register (``"%eax"``), a
    memory operand (``"-4(%ebp)"``), a bare symbol (``".L2"``), or empty text.
    """
    m = _IMM_NUM_RE.match(operand.strip())
    if m is None:
        return None
    text = m.group("val")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    # Base 16 when 0x-prefixed (int() accepts the prefix at base 16), else base 10.
    value = int(digits, 16) if digits[:2].lower() == "0x" else int(digits)
    return -value if negative else value


def _split_operands(operand_str: str) -> List[str]:
    """Split an AT&T operand string on top-level commas, keeping commas that sit
    inside an addressing-mode parenthesis together (so ``(%eax,%ecx,4)`` stays
    one operand).

    Mirrors the splitter used by the addressing / memory-traffic passes; kept
    local so this module stays self-contained like the other per-line analysers.
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


def immediates_in_instruction(text: str) -> List[int]:
    """Return the distinct numeric immediate values on one assembly instruction
    line, sorted ascending.

    ``text`` is a raw display-asm line. Labels (``.L2:``), directives
    (``.cfi_*``, ``.long``) and operand-less instructions (``ret``, ``leave``)
    contribute nothing and return ``[]``. A value that appears twice in the same
    instruction is reported once (the result is a per-instruction set).
    """
    stripped = text.strip()
    if not stripped or stripped.startswith(".") or stripped.endswith(":"):
        return []
    parts = stripped.split(None, 1)
    if len(parts) < 2:
        return []  # operand-less instruction (ret, leave, cltd, nop, …)
    values: Set[int] = set()
    for operand in _split_operands(parts[1]):
        v = parse_immediate(operand)
        if v is not None:
            values.add(v)
    return sorted(values)


def analyze_immediates(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with an ``immediate_values`` list (the
    distinct numeric immediate constants that line's assembly embeds, sorted
    ascending) and return a program-wide summary. Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    The summary is::

        {
          "value_totals": {value: instruction_count, ...},  # ordered by value
          "distinct":     <number of distinct values>,
        }

    ``value_totals`` counts, per value, the number of instructions that embed it
    (a value named twice in one instruction counts once — mirroring the register
    and addressing passes' "number of instructions that reference it"), ordered
    by value ascending. An asm line shared by two Python lines' mappings is
    counted once per owning Python line (the same convention as the register /
    addressing / branch passes); at gcc's ``.loc`` granularity that sharing is
    rare in practice. A line with no literals gets an empty ``immediate_values``
    list, mirroring how every per-line pass always attaches its field.
    """
    totals: Dict[int, int] = {}
    for mapping in line_map.values():
        line_values: Set[int] = set()
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                for value in immediates_in_instruction(asm_lines[asm_no - 1]):
                    line_values.add(value)
                    totals[value] = totals.get(value, 0) + 1
        mapping["immediate_values"] = sorted(line_values)

    value_totals = {value: totals[value] for value in sorted(totals)}
    return {"value_totals": value_totals, "distinct": len(value_totals)}
