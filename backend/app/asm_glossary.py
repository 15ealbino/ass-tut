"""
Assembly instruction glossary.

The cost-analysis and instruction-mix features answer *how much* and *what kind*
of work each Python line's assembly does. This module answers a third, more
elementary question that comes first when a learner opens the ASM pane: *what
does each of these mnemonics even mean?*

`build_asm_glossary` scans the compiled AT&T x86 output and returns one entry
per DISTINCT instruction mnemonic actually present, each with a plain-English
description. The category is not re-derived here — it is taken from
`app.compile.classify_category`, the single source of truth shared with the
instruction-mix feature, so the two features can never disagree about which
bucket an opcode belongs to.
"""
from typing import Dict, List, Tuple

# Prefix → description. Matched against the lowercased mnemonic (first token),
# first match wins, so a single entry covers every size-suffixed variant:
# "add" catches addl/addb, "j" catches every remaining conditional jump.
#
# Ordering rule: list a more specific prefix before any prefix it starts with.
# "movz"/"movs" precede "mov"; "fldz"/"fld1" precede "fld"; "jmp" precedes the
# catch-all "j"; "imul"/"idiv" precede "mul"/"div".
_GLOSSARY_PREFIXES: Tuple[Tuple[str, str], ...] = (
    # ── stack management ──────────────────────────────────────────────────
    ("push",  "push a value onto the stack (the stack grows downward)"),
    ("pop",   "pop the top value off the stack into a register"),
    ("enter", "set up a new stack frame"),
    ("leave", "tear down the current stack frame (mov %ebp→%esp, then pop %ebp)"),
    # ── call / return ─────────────────────────────────────────────────────
    ("call",  "call a function: push the return address, then jump to it"),
    ("ret",   "return to the caller using the pushed return address"),
    # ── data movement (widening variants before the generic 'mov') ────────
    ("movz",  "move with zero-extension: widen an unsigned value into a larger register"),
    ("movs",  "move with sign-extension: widen a signed value, preserving its sign"),
    ("mov",   "copy data between registers, memory, and immediates (no arithmetic)"),
    ("lea",   "load effective address: compute an address (or cheap arithmetic) without a memory access"),
    ("xchg",  "exchange the contents of two operands"),
    ("cmov",  "conditional move: copy only when a prior flag condition holds"),
    ("cltd",  "sign-extend %eax into %edx:%eax to set up a signed divide"),
    ("cdq",   "sign-extend %eax into %edx:%eax to set up a signed divide"),
    # ── integer arithmetic / logic ────────────────────────────────────────
    ("imul",  "signed integer multiply (an order of magnitude costlier than a shift/add)"),
    ("mul",   "unsigned integer multiply"),
    ("idiv",  "signed integer divide — very expensive (tens of CPU cycles)"),
    ("div",   "unsigned integer divide — very expensive (tens of CPU cycles)"),
    ("adc",   "add with carry"),
    ("add",   "integer addition"),
    ("sbb",   "subtract with borrow"),
    ("sub",   "integer subtraction"),
    ("inc",   "increment by one"),
    ("dec",   "decrement by one"),
    ("neg",   "arithmetic negation (two's complement)"),
    ("and",   "bitwise AND"),
    ("or",    "bitwise OR"),
    ("xor",   "bitwise XOR (xoring a register with itself is the idiomatic zero)"),
    ("not",   "bitwise NOT (one's complement)"),
    ("sal",   "shift arithmetic left — multiply by a power of two"),
    ("shl",   "shift logical left — multiply by a power of two"),
    ("sar",   "shift arithmetic right — signed divide by a power of two"),
    ("shr",   "shift logical right — unsigned divide by a power of two"),
    ("rol",   "rotate bits left"),
    ("ror",   "rotate bits right"),
    # ── compares / tests / branches ───────────────────────────────────────
    ("cmp",   "compare by subtracting two operands, setting flags but discarding the result"),
    ("test",  "bitwise-AND two operands to set flags, discarding the result"),
    ("set",   "set a byte to 0/1 from a flag condition (materialises a comparison result)"),
    ("jmp",   "unconditional jump"),
    ("loop",  "decrement %ecx and jump while it is nonzero"),
    ("j",     "conditional jump, taken only when the flags satisfy the condition"),
    # ── x87 floating point (specific constants before the generic loads) ──
    ("fldz",  "push the constant 0.0 onto the x87 register stack"),
    ("fld1",  "push the constant 1.0 onto the x87 register stack"),
    ("fild",  "load an integer and push it onto the x87 stack as a float"),
    ("fld",   "push a floating-point value onto the x87 register stack"),
    ("fistp", "convert the top x87 float to an integer, store it, and pop"),
    ("fst",   "store the top x87 float (fstp also pops it off the stack)"),
    ("fadd",  "floating-point addition (x87)"),
    ("fsub",  "floating-point subtraction (x87)"),
    ("fmul",  "floating-point multiplication (x87)"),
    ("fdiv",  "floating-point division (x87)"),
    ("fabs",  "floating-point absolute value (x87)"),
    ("fchs",  "floating-point sign change / negation (x87)"),
    ("fsqrt", "floating-point square root (x87)"),
    ("fucom", "compare two x87 floats, handling NaNs quietly"),
    ("fcom",  "compare two x87 floating-point values"),
    ("fxch",  "swap the top two x87 stack registers"),
    ("fnstsw", "store the x87 status word (used to read a float comparison's result)"),
    # ── misc ──────────────────────────────────────────────────────────────
    ("sahf",  "load %ah into the CPU flags (bridges an x87 compare into an integer branch)"),
    ("nop",   "no operation (padding / alignment)"),
    ("endbr", "control-flow-enforcement landing pad (CET); functionally a no-op"),
    ("hlt",   "halt the processor"),
    ("cpuid", "query CPU identification / feature information"),
)


def _describe(mnemonic: str) -> Tuple[str, str]:
    """Return (base, description) for a mnemonic.

    `base` is the matched glossary prefix (a canonical opcode family such as
    "mov" or "imul"); for an unrecognised mnemonic it is the mnemonic itself and
    the description is a generic fallback, so no opcode is ever dropped.
    """
    for prefix, description in _GLOSSARY_PREFIXES:
        if mnemonic.startswith(prefix):
            return prefix, description
    return mnemonic, f"x86 instruction '{mnemonic}' — consult an x86 reference for details"


def build_asm_glossary(asm_lines: List[str]) -> List[dict]:
    """Build a glossary of the distinct instruction mnemonics in `asm_lines`.

    `asm_lines` is the filtered display assembly (the same list the cost/mix
    passes consume). Blank lines, `.`-prefixed directives, and label lines
    (ending in `:`) carry no mnemonic and are skipped. Each remaining line's
    first whitespace-separated token is lowercased into a mnemonic; the first
    occurrence of each distinct mnemonic yields one entry
    `{mnemonic, base, category, description}`.

    The category is taken from `app.compile.classify_category` (imported lazily
    to avoid a circular import, since `compile` imports this module at module
    load) so the glossary and the instruction-mix feature share one
    classification. Entries are returned sorted by category display order, then
    mnemonic, for a stable response.
    """
    from app.compile import _CATEGORY_ORDER, classify_category

    seen: Dict[str, dict] = {}
    for line in asm_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(".") or stripped.endswith(":"):
            continue
        mnemonic = stripped.split(None, 1)[0].lower()
        if not mnemonic or mnemonic in seen:
            continue
        base, description = _describe(mnemonic)
        seen[mnemonic] = {
            "mnemonic": mnemonic,
            "base": base,
            "category": classify_category(mnemonic),
            "description": description,
        }

    return sorted(
        seen.values(),
        key=lambda e: (_CATEGORY_ORDER.get(e["category"], 99), e["mnemonic"]),
    )
