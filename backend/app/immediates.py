"""
Immediate-value map.

The addressing-mode feature counts *how many* of a Python line's asm operands are
immediates — the ``immediate`` bucket in its map. But a count is all it reports:
"2 immediate operands" never tells you *which* constants those operands are.

This module answers the sharper, more concrete question: *which literal constants
does each Python line's assembly actually embed?* ``analyze_immediates`` collects
the numeric immediate operands (``$5``, ``$100``, ``$-1``) each mapped
instruction carries and lists the distinct values per Python line, plus a
program-wide tally.

The lessons this teaches:
  * Pillar 1 (make the Python → C → asm mapping concrete): the single most direct
    thing a learner can see is their own literal travelling through the compiler.
    Write ``x = 5`` and the asm says ``movl $5, -4(%ebp)`` — the ``5`` you typed is
    right there as ``$5``. Listing the immediates next to the Python line that
    produced them turns "constants become immediates" from a claim into something
    you read off the screen. The map also surfaces the constants the compiler
    introduces that are *not* in your source — the ``$0`` of a ``return 0`` /
    zero-initialiser, the ``$1`` of a loop step — which is exactly the gap between
    the code you wrote and the code that runs.
  * Pillar 2 (spot the bug behind the asm): the constant a guard compares against
    is the bound the whole check hinges on. ``if i < 100`` compiles to
    ``cmpl $100, -4(%ebp)`` — reading ``$100`` straight off the disassembly is how
    you catch an off-by-one bound, a buffer size that does not match the array it
    guards, or a sentinel that was supposed to be one value and is quietly
    another. The magic number you have to notice is now listed for you.

Only NUMERIC immediates are collected. A ``$``-prefixed operand can also be the
*address* of a symbol or label (``$.LC0`` for a string literal, ``$main`` for a
function, ``$_shim_json_buf`` for the json helper's buffer); those are pointers,
not constant values, and are deliberately excluded so the map reads as "the
numbers in your program", not a jumble of relocation operands.
"""
import re
from typing import Dict, List, Set

# An AT&T immediate operand is ``$<value>``. This matches only the NUMERIC forms —
# an optional leading sign, then either a ``0x..`` hex literal or a run of decimal
# digits. The hex alternative is listed first so ``$0x10`` is read as hex ``16``
# rather than decimal ``0`` followed by a stray ``x10``. Symbolic operands
# (``$.LC0``, ``$main``, ``$_shim_json_buf``) begin with ``.``/letter/``_`` after
# the ``$`` and so never match — they are addresses, not constants (see module
# docstring). The leading ``\$`` is the immediate marker; displacements like the
# ``8`` in ``8(%ebp)`` carry no ``$`` and are intentionally not matched here (they
# are the stack-frame feature's job, not an immediate constant).
_IMM_TOKEN_RE = re.compile(r"\$(-?(?:0x[0-9a-fA-F]+|\d+))")


def canonical_immediate(value: int) -> str:
    """Render an immediate's integer value as its disassembly-style ``$N`` label.

    ``canonical_immediate(5) == "$5"``, ``canonical_immediate(-1) == "$-1"``,
    ``canonical_immediate(0) == "$0"``. Values are always normalised to DECIMAL,
    so a hex immediate ``$0x10`` in the asm and a decimal ``$16`` fold to the same
    ``$16`` label — the learner reads one consistent base.
    """
    return f"${value}"


def _parse_immediate(token: str) -> int:
    """Parse one captured immediate literal (without the ``$``) to its int value.

    ``token`` is the regex capture: a signed decimal (``"5"``, ``"-1"``) or a
    signed hex (``"0x10"``, ``"-0x8"``) literal. Hex is detected by the ``0x`` /
    ``-0x`` prefix and parsed base-16; everything else is base-10.
    """
    low = token.lower()
    if low.startswith(("0x", "-0x")):
        return int(token, 16)
    return int(token, 10)


def immediate_values_in_instruction(text: str) -> Set[int]:
    """Numeric immediate values referenced by one assembly instruction line.

    Returns the raw integer values of every ``$``-prefixed numeric operand on the
    line: ``{5}`` for ``movl $5, -4(%ebp)``, ``{100}`` for
    ``cmpl $100, -4(%ebp)``, ``{16}`` for the hex ``orl $0x10, %eax``, and the set
    of both for a line that carries two. A line with no immediate — a
    register-to-register ``addl %edx, %eax``, a label, a directive — returns the
    empty set. Symbolic ``$`` operands (``$.LC0``, ``$main``) are never matched, so
    an address-of operand is correctly left out (see module docstring).
    """
    return {_parse_immediate(m) for m in _IMM_TOKEN_RE.findall(text)}


def _sort_immediates(values) -> List[str]:
    """Sort immediate values ascending (negatives first) into ``$N`` labels."""
    return [canonical_immediate(v) for v in sorted(values)]


def analyze_immediates(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with an ``immediates`` list (the distinct
    numeric immediate constants that line's assembly embeds, as ``$N`` labels
    ordered by value ascending) and return a program-wide summary. Mutates
    ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    The summary is::

        {
          "immediate_totals": {label: instruction_count, ...},  # ordered by value
          "distinct":         <number of distinct immediate values program-wide>,
        }

    ``immediate_totals`` counts, per value, the number of instructions that
    reference it (a value named twice in one instruction counts once), ordered by
    numeric value ascending so negatives lead — the same label-keyed, value-ordered
    shape as the stack-frame map's ``slot_totals``. ``distinct`` is the key count,
    surfaced so the editor chip can read "N distinct constants" without re-counting.
    """
    totals: Dict[int, int] = {}
    for mapping in line_map.values():
        line_values: Set[int] = set()
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                values = immediate_values_in_instruction(asm_lines[asm_no - 1])
                line_values |= values
                for v in values:
                    totals[v] = totals.get(v, 0) + 1
        mapping["immediates"] = _sort_immediates(line_values)

    immediate_totals = {canonical_immediate(v): totals[v] for v in sorted(totals)}
    return {"immediate_totals": immediate_totals, "distinct": len(totals)}
