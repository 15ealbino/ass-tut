"""
Approximate cycle-cost estimate.

The cost-analysis feature counts *how many* x86 instructions each Python line
compiled to. But raw instruction count treats every instruction as equal, and
they are not: a single ``idiv`` costs tens of CPU cycles, while a ``mov`` or an
``add`` is roughly one. A Python line that compiles to three instructions — one
of them a divide — can be costlier than a line that compiles to eight moves.

This module answers the sharper question the instruction count only gestures at:
*which Python lines actually cost the most?* ``analyze_cycles`` assigns each
mapped instruction an approximate, latency-oriented weight and sums them per
Python line, so the eye is drawn to the genuinely expensive lines rather than
the merely long ones.

The lesson this teaches (mission pillar 2 — spotting bad/inefficient asm):
**instruction count is not cost.** Seeing "≈23 cyc" on a one-line ``a // b`` next
to "≈8 cyc" on a longer arithmetic line makes the divide's dominance concrete,
and comparing the program-wide cycle total against the instruction total shows
how much of the apparent work is cheap stack shuffling versus a few genuinely
costly operations.

IMPORTANT: these weights are deliberately coarse, RELATIVE teaching estimates —
not cycle-accurate figures. Real latencies vary by microarchitecture, operand
location, and pipelining. The goal is to rank lines by rough order-of-magnitude
cost, not to predict wall-clock time. The weights are documented alongside the
feature README so a learner can see exactly what each number means.
"""
from typing import Dict, List, Tuple

# Default cost for any mnemonic not singled out below: the one-cycle staples
# (mov, add, sub, lea, push, pop, cmp, test, and/or/xor, shifts, inc/dec, the
# sign-extends, nop, …). Everything cheap folds into this so only the notably
# expensive families need an explicit entry.
DEFAULT_WEIGHT = 1

# Prefix → approximate relative cycle weight. Matched against the lowercased
# mnemonic (first whitespace-separated token), first match wins, so a single
# entry covers every size-suffixed variant: "idiv" catches idivl/idiv, "call"
# catches calll, "fadd" catches faddp/faddl.
#
# Ordering rule (same as the glossary/mix tables): list a more specific prefix
# before any prefix it starts with. "idiv" precedes nothing it shadows;
# "fsqrt"/"fsub"/"fst" are distinct at the third character so their order is
# free, but "jmp" MUST precede the catch-all "j" and "imul"/"idiv" precede
# "mul"/"div" (they share no prefix, but keeping the pairs together documents
# intent).
#
# The magnitudes encode the teaching order: divide ≫ multiply / call ≫ float ALU
# > branch > the one-cycle default. They are intentionally round.
_WEIGHT_PREFIXES: Tuple[Tuple[str, int], ...] = (
    # ── integer divide — the dominant cost at -O0 ────────────────────────────
    ("idiv", 20),
    ("div",  20),          # also covers SSE divss/divsd — division is costly either way
    # ── x87 divide / square root — comparably expensive ──────────────────────
    ("fdiv",  18),
    ("fsqrt", 18),
    # ── integer multiply — costly, but an order below divide ─────────────────
    ("imul", 3),
    ("mul",  3),
    # ── call / return — pipeline disruption + stack traffic ──────────────────
    ("call", 4),
    ("ret",  3),
    # ── x87 floating-point ALU — slower than the integer ALU ─────────────────
    ("fmul", 5), ("fadd", 5), ("fsub", 5),
    ("fabs", 3), ("fchs", 3), ("fcom", 3), ("fucom", 3),
    ("fld",  2), ("fst", 2), ("fild", 2), ("fist", 2), ("fxch", 2),
    # ── control-flow branches — cheap, but above a plain move ────────────────
    ("jmp",  2),
    ("loop", 3),
    ("j",    2),           # every remaining conditional jump je/jne/jl/…
)


def cycle_weight(mnemonic: str) -> int:
    """Return the approximate relative cycle weight for an x86 mnemonic.

    ``mnemonic`` is the lowercased first whitespace-separated token of an
    instruction line (e.g. "idivl", "imull", "movl", "call"). An unrecognised
    or empty mnemonic — every cheap one-cycle staple — returns ``DEFAULT_WEIGHT``
    so it is always counted, never dropped. This total behaviour mirrors
    ``classify_category``: every instruction contributes to the line's estimate.
    """
    for prefix, weight in _WEIGHT_PREFIXES:
        if mnemonic.startswith(prefix):
            return weight
    return DEFAULT_WEIGHT


def analyze_cycles(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with a ``cycle_estimate`` (the summed
    approximate cycle weight of the instructions that line maps to) and return a
    program-wide summary. Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    The summary mirrors ``analyze_cost``'s shape so the two read as siblings::

        {
          "total_cycles": <sum of every mapped instruction's weight>,
          "hotspots":     [{"py_line": N, "cycles": W}, ...],  # costliest first
        }

    ``hotspots`` ranks the Python lines by estimated cost (descending), tie-broken
    by line number for determinism, and includes only lines that produced
    instructions. It is the cycle-weighted counterpart to the instruction-count
    hotspots — the two lists can disagree, which is exactly the lesson: the
    line with the most instructions is not always the costliest.
    """
    total = 0
    for mapping in line_map.values():
        cycles = 0
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                text = asm_lines[asm_no - 1].strip()
                mnemonic = text.split(None, 1)[0].lower() if text else ""
                cycles += cycle_weight(mnemonic)
        mapping["cycle_estimate"] = cycles
        total += cycles

    hotspots = [
        {"py_line": py_line, "cycles": mapping["cycle_estimate"]}
        for py_line, mapping in line_map.items()
        if mapping.get("cycle_estimate", 0) > 0
    ]
    hotspots.sort(key=lambda h: (-h["cycles"], h["py_line"]))

    return {"total_cycles": total, "hotspots": hotspots}
