"""
Compile endpoint logic: Python → C → x86 Assembly.
All subprocess calls run in a thread-pool to avoid blocking the event loop.
"""
import asyncio
import logging
import os
import re
import subprocess
import tempfile
from functools import partial
from typing import Dict, List, Set, Tuple

from app.transpiler import TranspileError, build_line_map, transpile

logger = logging.getLogger(__name__)

MAX_LINES = 200
MAX_CHARS = 10_000
TIMEOUT = 10  # seconds
# Cap simultaneous gcc subprocesses to prevent resource exhaustion from unauthenticated
# callers flooding the /compile endpoint.
MAX_CONCURRENT_GCC = 8

# Keyed by event-loop identity so each loop (including per-test loops in the test
# suite) gets its own semaphore without cross-loop sharing.
_GCC_SEMAPHORES: dict = {}


def _get_gcc_semaphore() -> asyncio.Semaphore:
    """Return a gcc semaphore bound to the current running event loop.

    Keying by loop identity ensures test isolation: pytest-asyncio creates a
    new loop per test function, so each test gets a fresh semaphore rather than
    reusing one from a previous (already-closed) loop.
    """
    loop = asyncio.get_running_loop()
    if loop not in _GCC_SEMAPHORES:
        _GCC_SEMAPHORES[loop] = asyncio.Semaphore(MAX_CONCURRENT_GCC)
    return _GCC_SEMAPHORES[loop]


class CompileError(Exception):
    pass


def _run_gcc(c_source: str) -> str:
    """Compile C source to x86 assembly, return asm text. Runs synchronously."""
    with tempfile.TemporaryDirectory() as tmp:
        c_path = os.path.join(tmp, "code.c")
        asm_path = os.path.join(tmp, "code.s")
        with open(c_path, "w") as f:
            f.write(c_source)
        result = subprocess.run(
            ["gcc", "-S", "-O0", "-m32", "-g1", "-o", asm_path, c_path],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if result.returncode != 0:
            stderr_clean = result.stderr.replace(c_path, "input.c")
            raise CompileError(f"GCC error:\n{stderr_clean}")
        with open(asm_path) as f:
            return f.read()


# ── Assembly cost analysis ─────────────────────────────────────────────────
#
# For each Python line we already know the exact display-asm lines it maps to.
# This module turns that raw mapping into an educational "cost" signal: how many
# real x86 instructions a Python line compiled to, plus flags for the few
# mnemonics that are notably expensive relative to the shift/add/mov staples.
#
# The lesson this teaches (mission pillar 2 — spotting bad/inefficient asm):
# `a * b` becomes an `imul`, `a // b` becomes an `idiv` (tens of cycles, far
# costlier than a shift), and every helper call is `call` overhead. Seeing the
# flag next to the Python line that caused it makes the Python→asm cost concrete.

# Prefix → flag. Matched against the instruction mnemonic (first token), so a
# single entry covers size-suffixed variants: "div" catches idivl/divl/divsd,
# "mul" catches imull/mull/mulsd, "call" catches calll.
_COST_FLAG_PREFIXES: Tuple[Tuple[str, str], ...] = (
    ("idiv", "div"),
    ("div", "div"),
    ("imul", "mul"),
    ("mul", "mul"),
    ("call", "call"),
)

# Ordering for a stable, meaningful flag list per line.
_FLAG_ORDER = {"div": 0, "mul": 1, "call": 2}


# ── Instruction-mix classification ──────────────────────────────────────────
#
# Where the cost flags above single out the *few* expensive mnemonics, the mix
# answers a different question: what KIND of work is each Python line's assembly?
# Every mapped instruction is sorted into exactly one of six categories so a
# learner can read the *shape* of a line, not just its instruction count.
#
# The lesson this teaches (mission pillar 2 — spotting bad/inefficient asm):
# at gcc -O0 every variable is spilled to the stack, so a line that reads as one
# arithmetic step in Python explodes into a pile of `mem` moves. Seeing "6 mem,
# 1 compute" next to a line makes that memory-traffic cost concrete, and trains
# the eye to notice when the *composition* — not just the count — looks wrong.
#
#   mem      data movement / memory traffic (mov, lea, movzx, x87 fld/fst, cltd)
#   compute  arithmetic + logic (add/sub/imul/idiv, and/or/xor, shifts, float ops)
#   branch   control flow: jumps, plus the cmp/test/setcc that drive them
#   call     call / return overhead (call, ret, leave)
#   stack    explicit stack management (push, pop, enter)
#   other    anything unrecognised (e.g. nop) — never silently miscounted
#
# Matched by mnemonic prefix (first match wins), so size-suffixed variants are
# covered by one entry: "mov" catches movl/movzbl/movsbl, "j" catches every
# conditional jump. Entries are ordered so no prefix shadows a more specific one.
_CATEGORY_PREFIXES: Tuple[Tuple[str, str], ...] = (
    # stack management
    ("push", "stack"), ("pop", "stack"), ("enter", "stack"),
    # call / return overhead
    ("call", "call"), ("leave", "call"), ("ret", "call"),
    # control flow — jumps, and the compares/setcc that feed a branch
    ("jmp", "branch"), ("loop", "branch"), ("cmp", "branch"),
    ("test", "branch"), ("set", "branch"), ("fcom", "branch"), ("fucom", "branch"),
    ("j", "branch"),                       # every remaining conditional jump je/jne/jl/…
    # arithmetic / logic — listed before "mem" so imul/idiv beat any mov match
    ("imul", "compute"), ("mul", "compute"), ("idiv", "compute"), ("div", "compute"),
    ("add", "compute"), ("sub", "compute"), ("adc", "compute"), ("sbb", "compute"),
    ("inc", "compute"), ("dec", "compute"), ("neg", "compute"), ("not", "compute"),
    ("and", "compute"), ("or", "compute"), ("xor", "compute"),
    ("sal", "compute"), ("sar", "compute"), ("shl", "compute"), ("shr", "compute"),
    ("rol", "compute"), ("ror", "compute"),
    ("fadd", "compute"), ("fsub", "compute"), ("fmul", "compute"), ("fdiv", "compute"),
    ("fabs", "compute"), ("fchs", "compute"), ("fsqrt", "compute"),
    # data movement / memory traffic
    ("mov", "mem"), ("lea", "mem"), ("xchg", "mem"), ("cmov", "mem"),
    ("clt", "mem"), ("cdq", "mem"), ("cwde", "mem"), ("cbw", "mem"),
    ("fld", "mem"), ("fst", "mem"), ("fild", "mem"), ("fist", "mem"), ("fxch", "mem"),
)

# Stable display/serialisation order for category maps.
_CATEGORY_ORDER = {"mem": 0, "compute": 1, "branch": 2, "call": 3, "stack": 4, "other": 5}


def classify_category(mnemonic: str) -> str:
    """Sort an x86 mnemonic into one of the six instruction-mix categories.

    `mnemonic` is the lowercased first whitespace-separated token of an
    instruction line (e.g. "movl", "idivl", "jne", "call"). Unlike
    `_classify_mnemonic`, this is total: an unrecognised or empty mnemonic
    returns "other" rather than None, so every counted instruction lands in
    exactly one bucket and the per-line counts always sum to the line's
    instruction total.
    """
    for prefix, category in _CATEGORY_PREFIXES:
        if mnemonic.startswith(prefix):
            return category
    return "other"


def _ordered_category_map(counts: Dict[str, int]) -> Dict[str, int]:
    """Return `counts` with zero entries dropped and keys in display order."""
    return {
        cat: counts[cat]
        for cat in sorted(counts, key=lambda c: _CATEGORY_ORDER.get(c, 99))
        if counts[cat] > 0
    }


# ── Register footprint analysis ─────────────────────────────────────────────
#
# The cost flags say *how expensive* a Python line's assembly is; the
# instruction mix says *what kind* of work it does. The register footprint says
# *where* the work happens: which x86 registers each Python line's assembly
# actually touches.
#
# The lessons this teaches:
#   * Pillar 1 (make the mapping concrete): at gcc -O0 every value flows through
#     a handful of registers and %ebp-relative stack slots. Seeing %eax appear
#     on nearly every line makes the accumulator-centric shape of the code real.
#   * Pillar 2 (spot non-obvious asm behaviour): integer division and the sign
#     extend that sets it up implicitly use the %edx:%eax pair. `q = a // b`
#     touches %edx even though %edx is nowhere in the operand text — exactly the
#     kind of hidden hardware behaviour that trips up someone reading a
#     disassembly. The footprint surfaces those implicit registers next to the
#     explicit ones.

# Sub-register spelling → canonical 32-bit register family. Covers the 8/16-bit
# spellings gcc emits under -m32 (`movb %al, ...`, `movw %dx, ...`) plus the
# 64-bit spellings, so the analyzer stays correct if ever pointed at non -m32
# output.
_REGISTER_FAMILY: Dict[str, str] = {
    "eax": "eax", "ax": "eax", "ah": "eax", "al": "eax", "rax": "eax",
    "ebx": "ebx", "bx": "ebx", "bh": "ebx", "bl": "ebx", "rbx": "ebx",
    "ecx": "ecx", "cx": "ecx", "ch": "ecx", "cl": "ecx", "rcx": "ecx",
    "edx": "edx", "dx": "edx", "dh": "edx", "dl": "edx", "rdx": "edx",
    "esi": "esi", "si": "esi", "sil": "esi", "rsi": "esi",
    "edi": "edi", "di": "edi", "dil": "edi", "rdi": "edi",
    "ebp": "ebp", "bp": "ebp", "bpl": "ebp", "rbp": "ebp",
    "esp": "esp", "sp": "esp", "spl": "esp", "rsp": "esp",
    "eip": "eip", "ip": "eip", "rip": "eip",
}

# Stable display / serialisation order for the register maps.
_REGISTER_ORDER = {
    "eax": 0, "ebx": 1, "ecx": 2, "edx": 3, "esi": 4, "edi": 5,
    "ebp": 6, "esp": 7, "eip": 8, "st": 9,
}

# Register operands in AT&T syntax are `%name`; x87 stack registers are
# `%st(0)`.."%st(7)". The alternation captures the parenthesised x87 form before
# the bare-word form so `%st(0)` is not truncated to `st`.
_REG_TOKEN_RE = re.compile(r"%(st\(\d+\)|\w+)")


def canonical_register(token: str) -> str:
    """Fold an x86 register spelling to its canonical 32-bit family name.

    ``token`` is a register name *without* the leading ``%`` (e.g. ``"eax"``,
    ``"al"``, ``"dx"``, ``"st(0)"``). Sub-registers fold to their family
    (``"al"``/``"ax"`` → ``"eax"``); x87 stack registers (``"st"``,
    ``"st(0)"``..``"st(7)"``) fold to ``"st"``. An unrecognised token is
    returned lowercased and unchanged so it is still counted, never silently
    dropped.
    """
    name = token.lower()
    if name.startswith("st"):      # st, st(0)..st(7)
        return "st"
    return _REGISTER_FAMILY.get(name, name)


def _implicit_registers(mnemonic: str) -> Tuple[str, ...]:
    """Canonical registers a mnemonic touches *implicitly* — registers that
    never appear in the operand text but are read/written by the hardware.

    Deliberately conservative so the footprint never over-claims: only the
    always-correct cases are listed. Integer division (``idiv``/``div``, always
    one-operand, dividend in ``%edx:%eax``) and the sign-extends that fill its
    high half (``cltd``/``cdq``/``cwd``/``cqto``) implicitly use the
    ``%edx:%eax`` pair. The one-operand ``mul``/``imul`` also use ``%edx:%eax``,
    but gcc -O0 emits the two/three-operand ``imul`` form (no ``%edx``) for
    ``a * b``, so multiply is left to its explicit operands to avoid a false
    ``%edx`` claim. SSE division (``divss``/``divsd``) is excluded by the
    integer-suffix check, since it touches ``%xmm`` registers, not
    ``%edx:%eax``.
    """
    if mnemonic.startswith("idiv"):
        return ("eax", "edx") if mnemonic[4:] in ("", "b", "w", "l", "q") else ()
    if mnemonic.startswith("div"):
        return ("eax", "edx") if mnemonic[3:] in ("", "b", "w", "l", "q") else ()
    if mnemonic in ("cltd", "cdq", "cwd", "cqto", "cqo"):
        return ("eax", "edx")
    return ()


def _registers_in_instruction(text: str) -> Set[str]:
    """Canonical registers referenced by one assembly instruction line —
    explicit operands plus any implicit hardware registers."""
    regs: Set[str] = {canonical_register(m) for m in _REG_TOKEN_RE.findall(text)}
    stripped = text.strip()
    mnemonic = stripped.split(None, 1)[0].lower() if stripped else ""
    regs.update(_implicit_registers(mnemonic))
    return regs


def _sort_registers(regs) -> List[str]:
    """Sort canonical register names into the stable display order."""
    return sorted(regs, key=lambda r: (_REGISTER_ORDER.get(r, 99), r))


def analyze_registers(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with a ``registers`` list (the canonical
    x86 registers that line's assembly touches) and return a program-wide
    summary ``{"register_totals": {reg: instruction_count}}``. Mutates
    ``line_map`` in place.

    ``asm_lines`` is the filtered display assembly, 1-indexed by the numbers
    stored in each entry's ``asm_lines`` (same convention as ``analyze_cost``).
    ``register_totals`` counts, per register, the number of instructions that
    reference it (a register named twice in one instruction counts once), so the
    totals read as "how many instructions touch this register".
    """
    totals: Dict[str, int] = {}
    for mapping in line_map.values():
        line_regs: Set[str] = set()
        for asm_no in mapping.get("asm_lines", []):
            # asm_no is 1-indexed into the filtered display asm; skip strays.
            if 1 <= asm_no <= len(asm_lines):
                regs = _registers_in_instruction(asm_lines[asm_no - 1])
                line_regs |= regs
                for r in regs:
                    totals[r] = totals.get(r, 0) + 1
        mapping["registers"] = _sort_registers(line_regs)

    register_totals = {r: totals[r] for r in _sort_registers(totals)}
    return {"register_totals": register_totals}


def _classify_mnemonic(mnemonic: str) -> str | None:
    """Return the cost flag for an x86 mnemonic, or None if it is unremarkable.

    `mnemonic` is the lowercased first whitespace-separated token of an
    instruction line (e.g. "idivl", "imull", "movl", "call").
    """
    for prefix, flag in _COST_FLAG_PREFIXES:
        if mnemonic.startswith(prefix):
            return flag
    return None


def analyze_cost(
    line_map: Dict[int, dict],
    asm_lines: List[str],
) -> dict:
    """Annotate each ``line_map`` entry with ``asm_count`` and ``flags`` and
    return a compact cost summary (``{total_instructions, hotspots}``).

    ``asm_lines`` is the list of filtered assembly text lines (1-indexed by the
    ``asm_lines`` numbers stored in each mapping). Mutates ``line_map`` in place.

    Alongside the existing ``asm_count`` / ``flags``, each entry also gains a
    ``category_counts`` map (instruction mix, zero categories omitted) and the
    returned summary carries a program-wide ``category_totals``.
    """
    total = 0
    category_totals: Dict[str, int] = {cat: 0 for cat in _CATEGORY_ORDER}
    for mapping in line_map.values():
        asm_nos = mapping.get("asm_lines", [])
        flags: set = set()
        categories: Dict[str, int] = {cat: 0 for cat in _CATEGORY_ORDER}
        for asm_no in asm_nos:
            # asm_no is 1-indexed into the filtered display asm.
            if 1 <= asm_no <= len(asm_lines):
                text = asm_lines[asm_no - 1].strip()
                mnemonic = text.split(None, 1)[0].lower() if text else ""
                flag = _classify_mnemonic(mnemonic)
                if flag is not None:
                    flags.add(flag)
                category = classify_category(mnemonic)
                categories[category] += 1
                category_totals[category] += 1
        count = len(asm_nos)
        total += count
        mapping["asm_count"] = count
        mapping["flags"] = sorted(flags, key=lambda f: _FLAG_ORDER.get(f, 99))
        mapping["category_counts"] = _ordered_category_map(categories)

    # Hotspots: Python lines ranked by instruction count (descending), then by
    # line number for determinism. Only lines that produced instructions.
    hotspots = [
        {
            "py_line": py_line,
            "asm_count": mapping["asm_count"],
            "flags": mapping["flags"],
        }
        for py_line, mapping in line_map.items()
        if mapping["asm_count"] > 0
    ]
    hotspots.sort(key=lambda h: (-h["asm_count"], h["py_line"]))

    return {
        "total_instructions": total,
        "hotspots": hotspots,
        "category_totals": _ordered_category_map(category_totals),
    }


def _parse_asm_line_map(asm_text: str) -> Tuple[Dict[int, List[int]], str]:
    """
    Parse GCC .loc directives to build c_lineno → [display_asm_lineno] mapping.
    Strips .loc and .file directives plus .debug_* sections from the returned
    display text so the frontend never sees them.
    """
    c_to_asm: Dict[int, List[int]] = {}
    current_c_line: int | None = None
    display_lines: List[str] = []
    in_debug_section = False

    for line in asm_text.splitlines():
        stripped = line.strip()

        # Enter / stay in a .debug_* section — skip everything in it
        if re.match(r'\.section\s+\.debug', stripped):
            in_debug_section = True
        if in_debug_section:
            # Leave when we hit a new .section that isn't .debug_*
            if re.match(r'\.section\b', stripped) and not re.match(r'\.section\s+\.debug', stripped):
                in_debug_section = False
            else:
                continue

        # .file directives are debug-only noise
        if stripped.startswith('.file'):
            continue

        # Parse .loc but don't emit it to the display
        m = re.match(r'\.loc\s+\d+\s+(\d+)', stripped)
        if m:
            current_c_line = int(m.group(1))
            continue

        display_lines.append(line)
        display_lineno = len(display_lines)  # 1-indexed in the filtered output

        is_instruction = (
            current_c_line is not None
            and stripped
            and not stripped.startswith('.')
            and not stripped.endswith(':')
        )
        if is_instruction:
            c_to_asm.setdefault(current_c_line, []).append(display_lineno)

    return c_to_asm, '\n'.join(display_lines)


async def compile_python(python_source: str) -> dict:
    lines = python_source.splitlines()
    if len(lines) > MAX_LINES:
        raise CompileError(f"Input too long: max {MAX_LINES} lines")
    if len(python_source) > MAX_CHARS:
        raise CompileError(f"Input too long: max {MAX_CHARS} characters")

    try:
        c_source, py_to_c = transpile(python_source)
    except TranspileError as e:
        raise CompileError(str(e))

    loop = asyncio.get_running_loop()
    sem = _get_gcc_semaphore()
    try:
        async with sem:
            asm_text = await asyncio.wait_for(
                loop.run_in_executor(None, partial(_run_gcc, c_source)),
                timeout=TIMEOUT + 1,
            )
    except asyncio.TimeoutError:
        logger.error("GCC timed out after %ds", TIMEOUT)
        raise CompileError("Compilation timed out")
    except CompileError:
        raise
    except Exception as e:
        logger.exception("Unexpected compilation failure")
        raise CompileError(f"Compilation failed: {e}")

    c_to_asm, filtered_asm = _parse_asm_line_map(asm_text)
    line_map = build_line_map(lines, py_to_c, c_to_asm)

    asm_lines = filtered_asm.splitlines()
    # Annotate each line_map entry with asm_count/flags and build the summary.
    cost_summary = analyze_cost(line_map, asm_lines)
    # Annotate each line_map entry with its register footprint and build the
    # program-wide register summary. Runs after analyze_cost so both passes
    # enrich the same line_map entries.
    register_summary = analyze_registers(line_map, asm_lines)

    return {
        "python_lines": lines,
        "c_code": c_source,
        "c_lines": c_source.splitlines(),
        "asm_code": filtered_asm,
        "asm_lines": asm_lines,
        "line_map": line_map,
        "cost_summary": cost_summary,
        "register_summary": register_summary,
    }
