"""
Loop-depth map — which Python lines run INSIDE a loop, and how deeply nested.

The sibling asm passes in ``app.compile`` each answer a question about a single
execution of a Python line: the cost pass says *how many* instructions it is,
the cycle pass says *how expensive* one pass through it is, the mix/register/
stack passes say *what shape* that work has. None of them answer the question
that decides a program's real cost: *how many times does this line run?*

A line's run count is dominated by loop nesting. An instruction at loop depth 2
runs (outer × inner) times; the single costliest `idiv` in a program is almost
never the one on a straight-line setup line, it is the cheap-looking one buried
two loops deep. This pass recovers that nesting straight from the assembly, the
way a reverse-engineer does: by reading the **back-edges**.

A loop back-edge is a branch whose target label sits ABOVE the branch — the jump
that loops control flow back to the top of the loop body. (A Python `for`/`while`
compiles to exactly one such backward branch at `gcc -O0`; an `if`/`else`
compiles only to FORWARD branches and so defines no loop.) The span from a
back-edge's target down to the back-edge itself is the loop body; the number of
such spans covering an instruction is its loop-nesting depth.

The lessons this teaches (mission pillars 1 and 2):

  * Pillar 1 (make the mapping concrete): the branch-flow map already teaches
    "backward branch = loop". This pass turns that single fact into structure —
    it recovers the whole loop nest from the back-edges alone and attributes a
    depth to every Python line, so "this line is inside two loops" reads right
    off your own code with no profiler.
  * Pillar 2 (spot inefficient / costly asm): depth is the multiplier the cost
    and cycle passes are missing. A learner who sees `cycle_estimate: 20`
    (a real `idiv`) AND `loop_depth: 2` on the same line has found the true
    hotspot — ~20 cycles paid on every one of (outer × inner) iterations — and
    the fix (hoist the divide out of the loop) follows directly. It also flags
    the pathological shapes: a line that is deep in a loop nest yet does
    redundant work is exactly the inefficiency this app exists to train the eye
    for.

The depth is a best-effort structural reading of the back-edges, in the spirit
of the cycle-cost pass's "coarse relative teaching estimate": it is exact for
the reducible loops this transpiler's `for`/`while` produce — including the
multi-back-edge case of a compound `or`/`and` condition, whose several backward
branches to one head label are merged into a single loop (see `loop_spans`) — and
it degrades gracefully (never raises, never over-counts a forward branch) on
anything more exotic. Classification is purely syntactic on the AT&T asm text so
it needs no second compile.
"""
import re
from typing import Dict, List, Tuple

# Full asm label: `.L2:`, `.LFB0:`, `main:`. A label occupies the whole stripped
# line (no operands) and may contain letters, digits, `_`, `.`, `$`. The trailing
# `:` distinguishes a label declaration from an operand mention of the same
# symbol. Kept local (same shape as the branch-flow map's `_LABEL_RE`) so this
# module stays self-contained like the other per-line analysers.
_LABEL_RE = re.compile(r"^([.\w$]+):$")


def _label_positions(asm_lines: List[str]) -> Dict[str, int]:
    """Map each label declaration to its 1-indexed display asm line.

    ``asm_lines`` is the filtered display assembly (same list handed to every
    other per-line pass). Only lines whose *entire* stripped form is
    ``<label>:`` are recorded — an operand mention of the same symbol elsewhere
    (``jmp .L4``) is not a declaration.
    """
    positions: Dict[str, int] = {}
    for idx, text in enumerate(asm_lines, start=1):
        m = _LABEL_RE.match(text.strip())
        if m:
            positions[m.group(1)] = idx
    return positions


def branch_target(text: str) -> str | None:
    """Return the direct label target of a branch instruction, or ``None``.

    ``text`` is a raw display-asm line. A branch is ``jmp``/``jmpl``, any
    conditional ``j*`` (``je``/``jne``/``jle``/…), or the ``loop*`` family — the
    same intra-file branch set the branch-flow map recognises. ``call``/``ret``
    are deliberately excluded (they are call overhead, not loop structure).

    Returns ``None`` for a non-branch, a label line, an operand-less branch, or
    an indirect target (``jmp *%eax``) — none of which names a static label this
    pass can resolve to a back-edge.

    Like ``compile._parse_branch`` (whose branch recognition this mirrors), the
    operand is assumed to carry no trailing comment (e.g. ``jmp .L2 # foo``),
    which holds because ``_run_gcc`` does not pass ``-fverbose-asm``. If that
    ever changes, both parsers must strip a trailing ``#``/``//`` comment off the
    target here, or the label lookup fails and the back-edge is misread as
    external.
    """
    stripped = text.strip()
    if not stripped or stripped.endswith(":"):
        return None
    parts = stripped.split(None, 1)
    mnemonic = parts[0].lower()
    if not (mnemonic.startswith("j") or mnemonic.startswith("loop")):
        return None
    if len(parts) < 2:
        return None  # operand-less / malformed — no static target
    target = parts[1].strip()
    if not target or target.startswith("*"):
        return None  # indirect target computed at run time
    return target


def loop_spans(asm_lines: List[str]) -> List[Tuple[int, int]]:
    """Return the ``(start, end)`` 1-indexed inclusive span of every loop in
    ``asm_lines``, one span per loop.

    A back-edge is a branch whose target label is declared STRICTLY ABOVE the
    branch's own line — the jump that loops control flow back to the top of a
    loop body. Forward branches (the if/else branch-around) have their target
    below and are not loops, so they are excluded; a branch whose target is not
    declared in this file (a tail call) is excluded too.

    One span is returned per LOOP, not per back-edge. A loop is identified by its
    head label (the back-edge target), and all back-edges to the same label are
    one loop: ``start`` is the label's line, ``end`` is the LAST (lowest)
    back-edge to it. This matters because a loop can have several back-edges to
    one head — a `while` with a compound `or` condition compiles at ``gcc -O0``
    to one conditional backward branch per short-circuited disjunct, all to the
    same body label (``while a or b`` → two ``jle .L3``). Deduplicating by target
    label keeps that a single depth-1 loop instead of miscounting it as nested.
    Distinct labels stay distinct spans, so genuine loop nests
    (an inner span contained in an outer one) are preserved.

    Spans are ordered by the first back-edge seen to each label (so an inner
    loop, whose back-edge occurs first in the stream, precedes its enclosing
    outer loop).
    """
    labels = _label_positions(asm_lines)
    # Target label → back-edge source lines (preserves first-seen label order).
    back_edges: Dict[str, List[int]] = {}
    for idx, text in enumerate(asm_lines, start=1):
        target = branch_target(text)
        if target is None:
            continue
        tgt_line = labels.get(target)
        if tgt_line is None:
            continue  # external target (tail call) — not an intra-file back-edge
        if tgt_line < idx:  # target above the branch → a backward loop edge
            back_edges.setdefault(target, []).append(idx)
    # One span per unique loop head: the head label down to its last back-edge.
    return [(labels[target], max(sources)) for target, sources in back_edges.items()]


def depth_at(asm_line: int, spans: List[Tuple[int, int]]) -> int:
    """Loop-nesting depth of a 1-indexed display asm line: the number of loop
    spans that cover it. ``0`` means straight-line code outside every loop."""
    return sum(1 for start, end in spans if start <= asm_line <= end)


def analyze_loops(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with a ``loop_depth`` int and return a
    program-wide summary. Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    Per line, ``loop_depth`` is the MAXIMUM nesting depth over the asm lines that
    line maps to — "the deepest loop this line's work runs inside". A loop-header
    line (the `for`/`while` itself) shares its body's depth because the loop's
    condition test re-executes on every iteration.

    The returned summary is::

        {
          "loop_count": <number of loops (distinct back-edge target labels)>,
          "max_depth":  <deepest nesting anywhere in the program>,
          "hotspots":   [{"py_line": n, "loop_depth": d}, ...],
        }

    ``max_depth`` is the maximum span overlap (read off the span endpoints, not
    the line map) so it reflects the true nesting even where the deepest point
    carries no ``.loc``. ``hotspots`` lists every Python line at depth >= 1 — the
    lines that run repeatedly — ranked by depth descending, then by line number
    for determinism (mirroring ``CostSummary`` / ``CycleSummary`` hotspots).
    """
    spans = loop_spans(asm_lines)

    for mapping in line_map.values():
        depth = 0
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                d = depth_at(asm_no, spans)
                if d > depth:
                    depth = d
        mapping["loop_depth"] = depth

    # Program-wide maximum nesting = the largest number of spans overlapping at
    # any point. A single sweep over the span endpoints finds it directly (each
    # span is active on its inclusive [start, end], so it closes at end + 1),
    # avoiding a per-asm-line rescan.
    events: List[Tuple[int, int]] = []
    for start, end in spans:
        events.append((start, 1))
        events.append((end + 1, -1))
    events.sort()
    active = max_depth = 0
    for _, delta in events:
        active += delta
        if active > max_depth:
            max_depth = active

    hotspots = [
        {"py_line": py_line, "loop_depth": mapping["loop_depth"]}
        for py_line, mapping in line_map.items()
        if mapping["loop_depth"] >= 1
    ]
    hotspots.sort(key=lambda h: (-h["loop_depth"], h["py_line"]))

    return {
        "loop_count": len(spans),
        "max_depth": max_depth,
        "hotspots": hotspots,
    }
