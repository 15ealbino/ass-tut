"""
Immediate-operand map — the literal constants each Python line bakes into its
machine code.

The sibling asm passes answer neighbouring questions: the instruction mix says
what KIND of work a line does, the register footprint says WHICH registers it
touches, the stack frame map says WHICH %ebp slots, and the addressing-mode map
says what FORM each operand takes — including a count of how many operands are
immediates. This pass answers the question that count only gestures at: *what are
the immediate constants, and what do they mean?*

Every immediate operand (an AT&T operand beginning with ``$``) is sorted into one
of three kinds:

    decimal   a plain numeric literal                      `$5`, `$-1`, `$0`
    hex       a hexadecimal numeric literal                `$0x10`, `$-0x1`
    symbol    an ADDRESS constant, not a value             `$.LC0`, `$main`,
                                                           `$_GLOBAL_OFFSET_TABLE_`

and — for the two numeric kinds — its integer value is recovered, so each Python
line reports both a per-kind count and the distinct numeric values it embeds.

The lessons this teaches (mission pillars 1 and 2):
  * Pillar 1 (make the mapping concrete at the VALUE level): your `x = 5` becomes
    `movl $5, -4(%ebp)` — the literal `5` you wrote appears, verbatim, as an
    immediate in the assembly. The sibling passes show the SHAPE of the lowering;
    this one lets you read your own constants straight out of the machine code.
  * Pillar 2 + reverse-engineering skill: reading immediate constants off a
    disassembly is a day-one RE task — magic numbers, buffer sizes, sentinel
    values, syscall numbers. The ``decimal``/``hex`` vs ``symbol`` split is the
    very first read an RE makes on an operand: is this a VALUE, or the ADDRESS of
    something? A ``symbol`` immediate like ``$.LC0`` is the address of a rodata
    entry — the place your string literals and printf format strings live — so
    seeing one tells you "a pointer into read-only data is being formed here".
  * Pillar 2 (the compiler writes constants you didn't): not every immediate came
    from your source. The ``$0`` of an implicit ``return 0``, loop steps, and
    frame arithmetic are all synthesized by the compiler. Surfacing every baked-in
    constant — not just the ones you typed — trains the eye to tell source
    constants from compiler-introduced ones, exactly the distinction that matters
    when a disassembly's constants don't line up with the code you expected.

Classification is purely syntactic on the AT&T operand text. An operand that does
not begin with ``$`` is not an immediate and is ignored (returns ``None``), so the
pass never miscounts a register or memory operand as a constant.
"""
import re
from typing import Dict, List, Optional

# Stable display / serialisation order for the immediate-kind maps. Ordered as a
# learner reads a constant: the two numeric forms first (the values you can read
# directly), then the symbolic address constant (a pointer, not a value).
_KIND_ORDER = {
    "decimal": 0,
    "hex": 1,
    "symbol": 2,
}

# A hexadecimal immediate body: optional sign, "0x"/"0X", then one-or-more hex
# digits and nothing else. Anchored so a symbol that merely starts with a hex-like
# run (none occur in gcc output, but defensively) is not mis-read as hex.
_HEX_BODY_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F]+$")
# A decimal immediate body: optional sign then one-or-more decimal digits only.
_DEC_BODY_RE = re.compile(r"^[+-]?[0-9]+$")


def classify_immediate(operand: str) -> Optional[str]:
    """Sort one AT&T operand into an immediate KIND, or return ``None``.

    Returns ``"decimal"`` / ``"hex"`` / ``"symbol"`` for an immediate operand
    (one beginning with ``$``), or ``None`` for any operand that is not an
    immediate (a register ``%eax``, a memory reference ``-4(%ebp)``, a bare code
    label ``.L2``). This ``None`` — rather than a catch-all bucket — is what keeps
    the pass from ever counting a non-constant as a constant; it is the one place
    this classifier is NOT total, by design.

    ``operand`` is a single already-split operand string (stripped defensively).

    * ``decimal``  — ``$`` then an optionally-signed run of decimal digits
      (``$5``, ``$-1``, ``$0``).
    * ``hex``      — ``$`` then an optionally-signed ``0x``-prefixed hex literal
      (``$0x10``, ``$-0x1``).
    * ``symbol``   — any other immediate: an address constant (``$.LC0``,
      ``$main``, ``$_GLOBAL_OFFSET_TABLE_``) — the ADDRESS of something, not a
      numeric value.
    """
    op = operand.strip()
    if not op.startswith("$"):
        return None
    body = op[1:]
    if not body:
        return "symbol"  # a lone "$" is malformed; treat as a (non-numeric) symbol
    if _HEX_BODY_RE.match(body):
        return "hex"
    if _DEC_BODY_RE.match(body):
        return "decimal"
    return "symbol"


def immediate_int_value(operand: str) -> Optional[int]:
    """Recover the integer value of a numeric immediate, or ``None``.

    Returns the ``int`` for a ``decimal`` or ``hex`` immediate (``$5`` → ``5``,
    ``$-1`` → ``-1``, ``$0x10`` → ``16``, ``$-0x1`` → ``-1``) and ``None`` for a
    ``symbol`` immediate (an address constant has no numeric value) or a
    non-immediate operand. ``int`` parsing is anchored by ``classify_immediate``,
    so a malformed body cannot slip through to raise here.
    """
    kind = classify_immediate(operand)
    body = operand.strip()[1:]  # drop the leading "$"
    if kind == "decimal":
        return int(body, 10)
    if kind == "hex":
        return int(body, 16)
    return None


def _split_operands(operand_str: str) -> List[str]:
    """Split an AT&T operand string on top-level commas, keeping commas that sit
    inside an addressing-mode parenthesis together (so ``(%eax,%ecx,4)`` stays one
    operand).

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


def immediates_in_instruction(text: str):
    """Yield ``(kind, value)`` for each immediate operand on one asm line.

    ``text`` is a raw display-asm line. Labels (``.L2:``), directives (``.long``,
    ``.cfi_*``) and operand-less instructions contribute nothing. ``kind`` is one
    of ``"decimal"`` / ``"hex"`` / ``"symbol"``; ``value`` is the recovered ``int``
    for the two numeric kinds and ``None`` for ``symbol``. Operands that are not
    immediates (registers, memory references, bare labels) are skipped.

    A ``.long``/``.value`` data directive can carry a numeric token, but it does
    not begin with ``$`` (it is a bare number, not an immediate operand), so the
    directive guard below plus the ``$`` test in ``classify_immediate`` together
    keep data payloads out of the instruction-immediate counts.
    """
    stripped = text.strip()
    if not stripped or stripped.startswith(".") or stripped.endswith(":"):
        return
    parts = stripped.split(None, 1)
    if len(parts) < 2:
        return  # operand-less instruction (ret, cltd, leave, nop, …)
    for op in _split_operands(parts[1]):
        kind = classify_immediate(op)
        if kind is not None:
            yield kind, immediate_int_value(op)


def _ordered_kind_map(counts: Dict[str, int]) -> Dict[str, int]:
    """Return ``counts`` with zero entries dropped and keys in display order."""
    return {
        kind: counts[kind]
        for kind in sorted(counts, key=lambda k: _KIND_ORDER.get(k, 99))
        if counts[kind] > 0
    }


def analyze_immediates(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with an ``immediate_counts`` map and an
    ``immediate_values`` list, and return a program-wide summary. Mutates
    ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    Per line:
      * ``immediate_counts`` — ``{kind: count}`` over the line's immediate
        OPERANDS (an instruction with two immediates contributes two), only the
        nonzero kinds, in stable display order (mirrors the zero-omitting
        instruction mix / addressing map).
      * ``immediate_values`` — the DISTINCT numeric values the line embeds
        (decimal + hex folded to ``int``), sorted ascending. Symbol immediates
        contribute to the counts but not here (an address has no value).

    Summary::

        {
          "immediate_totals": {kind: count, ...},   # operand counts, display order
          "distinct_values":  [int, ...],           # every distinct numeric value
                                                     # program-wide, sorted ascending
        }
    """
    totals: Dict[str, int] = {}
    all_values: set = set()
    for mapping in line_map.values():
        counts: Dict[str, int] = {}
        values: set = set()
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                for kind, value in immediates_in_instruction(asm_lines[asm_no - 1]):
                    counts[kind] = counts.get(kind, 0) + 1
                    totals[kind] = totals.get(kind, 0) + 1
                    if value is not None:
                        values.add(value)
                        all_values.add(value)
        mapping["immediate_counts"] = _ordered_kind_map(counts)
        mapping["immediate_values"] = sorted(values)

    return {
        "immediate_totals": _ordered_kind_map(totals),
        "distinct_values": sorted(all_values),
    }
