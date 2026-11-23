"""
EFLAGS producer/consumer map — the *invisible operand* a conditional jump reads.

The sibling asm passes each re-cut a Python line's assembly along one axis: the
instruction mix says what KIND of work it does, the register footprint says WHICH
registers it touches, the branch-sense map classifies a jump as signed/unsigned,
and the branch-flow map classifies it as forward/backward. This pass answers the
one question none of them do, and the one a reverse-engineer must answer to read
any comparison off a disassembly: **for a conditional jump, where were the flags
it tests set?**

x86 conditional control flow runs through the EFLAGS register, and EFLAGS appears
in *no operand*. `cmpl -8(%ebp), %eax` sets the flags; the `jge .L2` three lines
later reads them — yet nothing in `jge`'s text names what it compares. The data
dependency is entirely implicit, exactly like the implicit `%edx:%eax` the
register-footprint pass surfaces for integer division. This pass makes that
hidden channel countable by sorting every mapped instruction into one of three
flag roles (and leaving flag-neutral instructions — `mov`, `lea`, `jmp`, `push`,
`call` — uncounted, the way the branch-sense pass ignores non-jumps):

    set-cmp   a dedicated flag setter: `cmp` / `test` exist only to set EFLAGS
              for a following branch (they discard their result).
    set-alu   arithmetic / logic / shift that sets EFLAGS as a SIDE EFFECT of
              computing a value (`add`, `sub`, `and`, `or`, `xor`, `inc`, `dec`,
              `neg`, `imul`, shifts, ...). The flags are written whether or not
              anything reads them.
    use       a flag CONSUMER: a conditional jump (`jl`/`jge`/`je`/...), `setcc`,
              `cmov`, or the carry-chain `adc`/`sbb` — it reads EFLAGS.

The lessons this teaches (mission pillars 1 and 2):
  * Pillar 1 — make the Python→asm mapping concrete: a Python `if a < b:` lowers
    to exactly one `set-cmp` (`cmpl`) feeding one `use` (`jge`). Seeing that
    producer→consumer pair appear line-by-line turns "the comparison becomes a
    jump" from a slogan into two instructions coupled through a register you
    can name.
  * Pillar 2 — spot the non-obvious asm bug: reading backward from a `jcc` to
    the instruction that set its flags is a day-one reverse-engineering skill,
    precisely because the link is invisible in the operands. And it is a real
    bug surface: a `set-alu` instruction (an `add`, an `and`) that lands between
    a `cmp` and its `jcc` silently overwrites the flags the branch depends on —
    the compare no longer decides the branch. gcc -O0 keeps the `cmp` adjacent
    to its `jcc`, so a healthy program here shows `set-cmp` and `use` in step;
    the `set-alu` count is every instruction quietly writing flags that *a*
    branch could come to depend on — the hazard this map trains the eye to see.

Classification is purely syntactic on the lowercased mnemonic (the first
whitespace-separated token), mirroring the branch-sense pass. Each instruction
lands in at most one role; an instruction with no EFLAGS interaction is left
uncounted rather than forced into a bucket, so the per-line counts read as "how
much of this line is flag traffic", not a share of its total instruction count.
"""
from typing import Dict, List, Optional

# Stable display / serialisation order for the flag-effect maps. Ordered as the
# producer→consumer story reads: the dedicated comparators first, then the
# side-effect flag writers, then the consumers that read what they set.
_EFFECT_ORDER = {"set-cmp": 0, "set-alu": 1, "use": 2}

# SSE scalar/packed arithmetic suffixes. These FP instructions do NOT write
# EFLAGS, and gcc -m32 -O0 uses the x87 `f*` mnemonics (also flag-neutral here)
# for this transpiler's doubles anyway. Guarded so an integer prefix like "add"
# never misreads an "addsd"/"mulss" as a flag-setting integer op. (The SSE
# compares `comiss`/`ucomisd` *do* write EFLAGS, but the fixed x87 build never
# emits them, so leaving them uncounted here is conservative, not wrong.)
_SSE_SUFFIXES = ("ss", "sd", "ps", "pd")

# Flag CONSUMERS that are not jumps: setcc (`sete`, `setl`, ...), `cmov*`, and
# the carry-chain `adc`/`sbb` (which read CF). Checked before the producer
# tables so `adc`/`sbb` — which also WRITE flags — are reported by the role that
# matters when reading control flow: they consume a carry a prior op produced.
_USE_PREFIXES = ("set", "cmov", "adc", "sbb")

# Dedicated flag setters: `cmp` / `test` compute nothing a later instruction
# uses except the flags — they exist to drive a branch.
_SETCMP_PREFIXES = ("cmp", "test")

# Arithmetic / logic / shift that writes EFLAGS as a side effect of producing a
# value. Deliberately ABSENT: `mov`, `lea`, and `not` — none of the three touch
# EFLAGS (a classic disassembly-reading trap, `lea`/`not` especially), so they
# must not be counted as flag writers.
_SETALU_PREFIXES = (
    "add", "sub", "and", "or", "xor",
    "inc", "dec", "neg",
    "imul", "mul", "idiv", "div",
    "sal", "sar", "shl", "shr", "rol", "ror",
)


def classify_flag_effect(mnemonic: str) -> Optional[str]:
    """Sort one x86 mnemonic into its EFLAGS role, or ``None`` if flag-neutral.

    Returns ``"set-cmp"`` (a dedicated `cmp`/`test` flag setter), ``"set-alu"``
    (arithmetic/logic that sets flags as a side effect), ``"use"`` (a flag
    consumer: conditional jump, `setcc`, `cmov`, `adc`/`sbb`), or ``None`` for an
    instruction that neither reads nor writes EFLAGS (`mov`, `lea`, `jmp`,
    `push`, `pop`, `call`, `ret`, `leave`, `nop`, the sign-extends `cltd`/`cdq`,
    and the x87/SSE FP ops under the fixed build).

    ``mnemonic`` is the lowercased first whitespace-separated token of an
    instruction line (e.g. ``"cmpl"``, ``"jge"``, ``"addl"``, ``"movl"``). Size
    suffixes are handled by prefix match (``"cmpl"`` classifies the same as
    ``"cmp"``). Each mnemonic yields at most one role.
    """
    m = mnemonic.lower()
    if not m:
        return None

    # Jumps first. A CONDITIONAL jump reads EFLAGS; the unconditional `jmp`
    # reads nothing; the `jecxz`/`jcxz` family tests %ecx, not the flags — so
    # neither of the latter two is a flag use. Matched before the prefix tables
    # because "j" would otherwise never be reached.
    if m.startswith("jmp"):
        return None
    if m.startswith("jecxz") or m.startswith("jcxz"):
        return None
    if m.startswith("j"):
        return "use"

    # SSE FP arithmetic writes no EFLAGS (see note). Checked before the integer
    # prefix tables so "addsd"/"mulss"/"cmpsd" are not misread as integer ops.
    if m.endswith(_SSE_SUFFIXES):
        return None

    # Non-jump flag consumers (setcc / cmov / adc / sbb). Before the producer
    # tables so the carry-chain ops report their consumer role (see note).
    if m.startswith(_USE_PREFIXES):
        return "use"
    # Dedicated flag setters.
    if m.startswith(_SETCMP_PREFIXES):
        return "set-cmp"
    # Side-effect flag setters.
    if m.startswith(_SETALU_PREFIXES):
        return "set-alu"
    return None


def _ordered_effect_map(counts: Dict[str, int]) -> Dict[str, int]:
    """Return ``counts`` with zero entries dropped and keys in display order."""
    return {
        effect: counts[effect]
        for effect in sorted(counts, key=lambda e: _EFFECT_ORDER.get(e, 99))
        if counts[effect] > 0
    }


def analyze_flag_effects(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with a ``flag_effect_counts`` map and
    return a program-wide summary ``{"flag_totals": {role: count, ...}}``.
    Mutates ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost`` and
    the other per-line passes). Out-of-range indices are skipped defensively.

    Per line, ``flag_effect_counts`` carries only the nonzero roles in display
    order (``set-cmp`` < ``set-alu`` < ``use``; mirroring the zero-omitting
    instruction mix); ``flag_totals`` is the same summed across every line —
    empty when the program has no flag traffic at all. Counts are of
    INSTRUCTIONS, each contributing its single role, so a line's counts sum to
    the number of its instructions that touch EFLAGS (never more than its total).
    """
    totals: Dict[str, int] = {}
    for mapping in line_map.values():
        counts: Dict[str, int] = {}
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                text = asm_lines[asm_no - 1].strip()
                mnemonic = text.split(None, 1)[0].lower() if text else ""
                effect = classify_flag_effect(mnemonic)
                if effect is not None:
                    counts[effect] = counts.get(effect, 0) + 1
                    totals[effect] = totals.get(effect, 0) + 1
        mapping["flag_effect_counts"] = _ordered_effect_map(counts)

    return {"flag_totals": _ordered_effect_map(totals)}
