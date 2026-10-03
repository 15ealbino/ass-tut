"""
Addressing-mode map — how each Python line's assembly *forms its addresses*.

The sibling asm passes answer neighbouring questions: the instruction mix says
what KIND of work a line does, memory traffic says how many loads/stores it
performs, the register footprint says WHICH registers it touches, and the stack
frame map says WHICH %ebp slots. This pass answers the orthogonal question a
reverse-engineer asks first when reading an operand: *what addressing mode is
this?* — is the value an immediate constant, a register, a plain stack slot, or
a scaled array element?

Every operand of every mapped instruction is sorted into exactly one of five
addressing modes:

    immediate     a literal / address constant                 `$5`, `$.LC0`
    register      register-direct                               `%eax`, `%st(0)`
    displacement  base register + displacement (a stack local)  `-4(%ebp)`, `(%eax)`
    indexed       base + scaled index (an array element)        `-24(%ebp,%eax,4)`
    segment       segment-relative memory (a stack canary)      `%gs:20`
    direct        a bare symbol / code target                   `.L2`, `helper`

The lessons this teaches (mission pillars 1 and 2):
  * Pillar 1 (make the mapping concrete): at gcc -O0 nearly every operand is a
    `displacement` mode off %ebp, because every local is spilled to the stack.
    Seeing that dominate makes the "everything lives on the stack" story real.
  * Pillar 2 + reverse-engineering skill: reading addressing modes off a
    disassembly is a day-one RE task, and one mode carries an outsized signal —
    the SCALED-INDEX form `(%ebp,%eax,4)`. That `,4` scale is the fingerprint of
    array-element access: `xs[i]` in Python becomes exactly this mode, the index
    register times the element size added to the base. Spotting an `indexed`
    operand tells you "an array is being walked here" at a glance, and the
    absence of a bounds check around one is how out-of-range array reads hide in
    plain sight.
  * Pillar 2 (security signal): the `segment` mode is a memory access through a
    segment register (`%gs:20`). At -O0 gcc's default `-fstack-protector-strong`
    emits exactly this to load and check the stack canary on any function with a
    local array — precisely the array-indexing programs this feature is built
    around. Seeing a `segment` operand appear is the stack protector made
    visible: a security mechanism you can read straight off the disassembly.

Classification is purely syntactic on the AT&T operand text, and it is *total*:
an unrecognised operand falls into `direct` rather than being dropped, so the
per-line mode counts always sum to the line's total operand count (mirroring the
total design of `classify_category` / `cycle_weight`).
"""
import re
from typing import Dict, List

# Stable display / serialisation order for the addressing-mode maps. Ordered as a
# learner reads a program's cost: the cheap operand forms first (immediate,
# register), then the -O0 stack-slot staple (displacement), then the array-access
# highlight (indexed), then the segment-relative canary access, then the
# catch-all (direct).
_MODE_ORDER = {
    "immediate": 0,
    "register": 1,
    "displacement": 2,
    "indexed": 3,
    "segment": 4,
    "direct": 5,
}

# A segment-override memory operand: a segment register followed by ':', e.g.
# `%gs:20` or `%fs:(%eax)`. gcc's default -fstack-protector-strong loads and
# checks the stack canary through `%gs:` (i386) on any function with a local
# array, so this form appears in exactly the array-indexing programs this feature
# targets. Checked BEFORE the register test — `%gs:20` starts with `%` but is a
# memory access, not register-direct — and before the parenthesised-memory test,
# so both `%gs:20` and the rarer `%gs:(%eax)` classify as `segment`. The trailing
# ':' is required: a bare `%gs` (e.g. `push %gs`) is a register-direct operand.
_SEGMENT_RE = re.compile(r"^%(?:cs|ds|es|fs|gs|ss):")

# An AT&T memory operand always carries a parenthesised base/index group holding
# at least one register: `-4(%ebp)`, `(%eax)`, `(%ebp,%eax,4)`, `.L4(,%eax,4)`,
# `sym@GOTOFF(%ebx)`. Immediates (`$5`), register-direct operands (`%eax`,
# `%st(0)` — parens but no `%` inside them), and bare symbols (`.L2`, `helper`)
# carry no such `(...%...)` group, so this cleanly separates memory operands from
# the rest.
_MEM_GROUP_RE = re.compile(r"\([^)]*%[^)]*\)")


def classify_operand(operand: str) -> str:
    """Sort one AT&T assembly operand into its addressing mode.

    Returns one of ``"immediate"`` / ``"register"`` / ``"displacement"`` /
    ``"indexed"`` / ``"segment"`` / ``"direct"``. Total by construction: any
    operand that is not an immediate, a segment-relative access, a register-direct,
    or a parenthesised memory reference falls into ``"direct"`` (bare symbols and
    code targets), so no operand is dropped.

    ``operand`` is a single already-split operand string (no surrounding
    whitespace assumed — it is stripped here defensively).

    * ``immediate``   — begins with ``$`` (a literal value or an address
      constant like ``$.LC0``).
    * ``segment``     — a segment-override memory access: a segment register
      followed by ``:`` (``%gs:20``, ``%fs:(%eax)``). Checked before the register
      and memory tests because it begins with ``%`` yet is a memory reference; a
      bare ``%gs`` without the ``:`` is register-direct, not this.
    * memory operand  — contains a ``(...%...)`` base/index group. It is
      ``indexed`` when that group carries a comma (a base+index[,scale] form —
      the array-element fingerprint) and ``displacement`` otherwise (base +
      optional displacement — the plain stack-slot form).
    * ``register``    — begins with ``%`` and is not a memory operand
      (``%eax``; also the x87 ``%st(0)`` whose parens hold no ``%``).
    * ``direct``      — everything else: a bare symbol or code target
      (``.L2``, ``helper``), including an indirect target like ``*%eax``.
    """
    op = operand.strip()
    if not op:
        return "direct"
    if op.startswith("$"):
        return "immediate"
    if _SEGMENT_RE.match(op):
        return "segment"
    mem = _MEM_GROUP_RE.search(op)
    if mem is not None:
        # A comma inside the base/index parentheses means an index register is
        # present (base+index[,scale]) — the scaled-array-access form.
        return "indexed" if "," in mem.group(0) else "displacement"
    if op.startswith("%"):
        return "register"
    return "direct"


def _split_operands(operand_str: str) -> List[str]:
    """Split an AT&T operand string on top-level commas, keeping the commas that
    sit inside an addressing-mode parenthesis together (so ``(%eax,%ecx,4)``
    stays one operand rather than three).

    Mirrors the splitter used by the memory-traffic pass; kept local so this
    module stays self-contained like the other per-line analysers.
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


def operand_modes(text: str) -> List[str]:
    """Return the addressing mode of each operand on one assembly instruction
    line, in source order.

    ``text`` is a raw display-asm line. Labels (``.L2:``), directives (``.cfi_*``,
    ``.long``) and any operand-less instruction (``ret``, ``cltd``, ``leave``)
    contribute nothing and return ``[]`` — only real operands are classified.
    """
    stripped = text.strip()
    if not stripped or stripped.startswith(".") or stripped.endswith(":"):
        return []
    parts = stripped.split(None, 1)
    if len(parts) < 2:
        return []  # operand-less instruction (ret, cltd, leave, nop, …)
    return [classify_operand(op) for op in _split_operands(parts[1])]


def _ordered_mode_map(counts: Dict[str, int]) -> Dict[str, int]:
    """Return ``counts`` with zero entries dropped and keys in display order."""
    return {
        mode: counts[mode]
        for mode in sorted(counts, key=lambda m: _MODE_ORDER.get(m, 99))
        if counts[mode] > 0
    }


def analyze_addressing(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with an ``addressing_counts`` map and
    return a program-wide summary ``{"addressing_totals": {mode: count, ...}}``.
    Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    Per line, ``addressing_counts`` carries only the nonzero modes in display
    order (mirroring the zero-omitting instruction mix); ``addressing_totals`` is
    the same, summed across every line — empty when the program has no operands
    at all. Counts are of OPERANDS (an instruction with two memory operands
    contributes two), so the per-line counts sum to the line's operand total.
    """
    totals: Dict[str, int] = {}
    for mapping in line_map.values():
        counts: Dict[str, int] = {}
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                for mode in operand_modes(asm_lines[asm_no - 1]):
                    counts[mode] = counts.get(mode, 0) + 1
                    totals[mode] = totals.get(mode, 0) + 1
        mapping["addressing_counts"] = _ordered_mode_map(counts)

    return {"addressing_totals": _ordered_mode_map(totals)}
