"""
Arithmetic strength hints — a source-level companion to the asm-scan passes.

The cost / mix / register / stack / memory passes in ``app.compile`` all answer
questions about the *assembly*: how much of it, what kind, where it lives. This
pass works from the other end of the pipeline — the Python AST — to teach one
specific thing the raw asm does not spell out: **which arithmetic the compiler
strength-reduces, and which it cannot.**

The surprising, teachable fact (verified against ``gcc -O0 -m32``, the exact
build this app uses) is that even with *no optimization* gcc already rewrites
arithmetic by a compile-time constant:

  * ``a * 8``  → a single left shift ``sal $3`` — never an ``imul``.
  * ``n // 4`` → an arithmetic shift ``sar $2`` plus a small sign-bias fixup
    (signed ``//`` is not a bare shift for negative values) — never an ``idiv``.
  * ``n % 8``  → shifts plus a bitwise ``and $7`` — never an ``idiv``.

The one case gcc *cannot* strength-reduce is a divide or modulo by a **runtime
value** (``a / b``, ``a % b``): that compiles to a real ``idiv``, the single most
expensive common integer instruction (tens of CPU cycles).

The lesson this teaches (mission pillars 1 and 2):

  * Pillar 1 — make the Python→asm mapping concrete: the hint points a learner at
    the exact instruction their line became. "Your ``a * 8`` is that ``sal $3``"
    turns an abstract mapping into a specific instruction to go look at.
  * Pillar 2 — spot inefficient assembly and understand the fix: it trains the
    eye to tell a *cheap* shift-based reduction from a genuinely expensive
    ``idiv``, and surfaces the signed-division sign-fix subtlety that trips up
    people reading a disassembly.

Hints are derived from the AST, not the assembly, so they are stable across gcc
versions and never fire on a folded constant expression (``2 * 3``), where no
instruction reaches the pane at all — a hint fires only when a genuine runtime
value is involved.
"""
import ast
from typing import Dict, List, Optional, Tuple

# ── Hint kinds ───────────────────────────────────────────────────────────────
#
# Three kinds, ordered for a stable per-line and summary listing. The message is
# the teaching payload; the kind is the stable machine-readable label the
# frontend can group / mark by.
KIND_MUL_POW2 = "mul-pow2"   # a * 2**k  → the compiler emits a left shift
KIND_DIV_POW2 = "div-pow2"   # a /,//,% 2**k → shifts + sign fix / bitwise AND
KIND_DIV_VAR = "div-var"     # a /,//,% <runtime value> → a real, costly idiv

# Stable display / serialisation order (mirrors the ordered maps in app.compile).
_KIND_ORDER = {KIND_MUL_POW2: 0, KIND_DIV_POW2: 1, KIND_DIV_VAR: 2}

# Message for a divide/modulo by a non-constant divisor — the one arithmetic the
# compiler genuinely cannot strength-reduce.
_MSG_DIV_VAR = (
    "Dividing or taking a remainder by a runtime value compiles to a real "
    "`idiv` — the most expensive common integer instruction (tens of CPU "
    "cycles). Unlike a constant divisor, the compiler cannot strength-reduce "
    "it to shifts. Hoist it out of hot loops where you can."
)


def _is_constant(node: ast.expr) -> bool:
    """True if ``node`` is a bare literal constant.

    Used to skip constant-only expressions like ``2 * 3`` or ``6 // 2``: gcc
    evaluates those at compile time, so no instruction reaches the asm pane and a
    strength hint would point at nothing. Only genuine runtime operands (names,
    calls, subscripts, nested arithmetic) get hinted.
    """
    return isinstance(node, ast.Constant)


def _power_of_two_operand(node: ast.expr) -> Optional[int]:
    """Return ``n`` if ``node`` is a positive integer literal that is a power of
    two ``>= 2`` (i.e. ``2, 4, 8, 16, ...``), else ``None``.

    ``1`` (``2**0``) is excluded: multiplying/dividing by one is a no-op the
    front end drops, so it has no instructive shift to point at. Booleans are
    excluded even though ``True``/``False`` are ``int`` subclasses.
    """
    if not isinstance(node, ast.Constant):
        return None
    value = node.value
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value >= 2 and (value & (value - 1)) == 0:
        return value
    return None


def _shift_amount(n: int) -> int:
    """Base-2 log of an exact power of two (``8 -> 3``). Caller guarantees the
    input is a power of two ``>= 2`` (see ``_power_of_two_operand``)."""
    return n.bit_length() - 1


def hint_for_binop(node: ast.BinOp) -> Optional[Tuple[str, str]]:
    """Return ``(kind, message)`` for a single binary-operation node, or ``None``.

    Pure and side-effect free so it can be unit-tested without gcc or the AST
    walk. The rules mirror what ``gcc -O0 -m32`` actually emits:

    * ``Mult`` where one operand is a power-of-two literal **and the other
      operand is not itself a constant** → ``mul-pow2`` (gcc emits a left shift).
    * ``Div`` / ``FloorDiv`` / ``Mod``:
        - divisor is a power-of-two literal **and the dividend is not a
          constant** → ``div-pow2`` (gcc emits shifts + a sign fix / bitwise AND);
        - divisor is **not a constant at all** (a variable, a call, ...) →
          ``div-var`` (a real, costly ``idiv``).
        - divisor is a non-power-of-two *constant* (``a // 3``) → ``None``: gcc
          rewrites it as a magic-number multiply, neither the clean shift case
          nor a true ``idiv``, so it is deliberately left un-hinted.
        - both operands constant → ``None`` (folded at compile time).

    Anything else → ``None``.
    """
    op = node.op
    if isinstance(op, ast.Mult):
        for operand, other in ((node.left, node.right), (node.right, node.left)):
            n = _power_of_two_operand(operand)
            if n is not None and not _is_constant(other):
                k = _shift_amount(n)
                return (
                    KIND_MUL_POW2,
                    f"Multiplication by {n} is a multiply by a power of two "
                    f"(2**{k}). Even at -O0 the compiler strength-reduces it to a "
                    f"single left shift `sal ${k}` — there is no `imul` in the "
                    f"asm for this line. A variable multiply like `a * b` cannot "
                    f"be reduced and stays a full `imul`.",
                )
        return None

    if isinstance(op, (ast.Div, ast.FloorDiv, ast.Mod)):
        n = _power_of_two_operand(node.right)
        if n is not None:
            # A power-of-two divisor with a runtime dividend is the teachable
            # strength-reduction case; a constant dividend is folded away.
            if _is_constant(node.left):
                return None
            k = _shift_amount(n)
            return (
                KIND_DIV_POW2,
                f"Division/modulo by {n} is a power of two (2**{k}). Even at -O0 "
                f"the compiler avoids the costly `idiv`: `//` becomes an "
                f"arithmetic shift `sar ${k}` plus a small sign-bias fixup "
                f"(signed division is not a bare shift for negative values), and "
                f"`%` becomes a bitwise `and ${n - 1}` after that fixup. Look for "
                f"the shifts in the asm — there is no `idiv`.",
            )
        # A non-constant divisor is the one case gcc cannot strength-reduce: a
        # genuine idiv. A non-power-of-two *constant* divisor (e.g. `a // 3`) is
        # rewritten as a magic-number multiply and is deliberately not hinted.
        if not _is_constant(node.right):
            return (KIND_DIV_VAR, _MSG_DIV_VAR)
        return None

    return None


def collect_hints(python_source: str) -> Dict[int, List[dict]]:
    """Walk ``python_source`` and return ``{py_lineno: [ {kind, message}, ... ]}``.

    Every ``BinOp`` in the tree is classified by :func:`hint_for_binop` and, when
    it yields a hint, attributed to the operation's source line. Multiple hits of
    the *same kind* on one line are de-duplicated (a line like ``a*8 + b*4``
    reports a single ``mul-pow2`` entry, keeping the first message) so the signal
    stays quiet; distinct kinds on one line are all kept, in ``_KIND_ORDER``.

    A syntax error yields an empty map rather than raising — defensive only, since
    this runs after a successful transpile, whose parse has already succeeded.
    """
    try:
        tree = ast.parse(python_source)
    except SyntaxError:
        return {}

    # line -> {kind: message}, preserving first-seen message per (line, kind).
    per_line: Dict[int, Dict[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        hint = hint_for_binop(node)
        if hint is None:
            continue
        kind, message = hint
        line = getattr(node, "lineno", None)
        if line is None:
            continue
        kinds = per_line.setdefault(line, {})
        kinds.setdefault(kind, message)

    result: Dict[int, List[dict]] = {}
    for line, kinds in per_line.items():
        ordered = sorted(kinds.items(), key=lambda kv: _KIND_ORDER.get(kv[0], 99))
        result[line] = [{"kind": k, "message": m} for k, m in ordered]
    return result


def analyze_strength(
    line_map: Dict[int, dict],
    python_source: str,
) -> dict:
    """Annotate each ``line_map`` entry with a ``strength_hints`` list and return
    a program-wide summary. Mutates ``line_map`` in place.

    Unlike the asm-scan passes (which key off ``mapping["asm_lines"]``), this pass
    keys off the Python source line number — the ``line_map`` dict key — so it
    needs no assembly. Every mapped line receives a ``strength_hints`` list
    (empty when the line has no flagged arithmetic), mirroring how the other
    passes always attach their field.

    The returned summary is::

        {
          "hint_totals": {kind: number_of_lines_with_that_kind, ...},  # ordered
          "hints":       [{"py_line": n, "kind": k, "message": m}, ...],
        }

    ``hint_totals`` omits zero entries and is ordered by kind; ``hints`` is
    ordered by ``(py_line, kind)``. The summary is built from every hinted line
    in the source, so a hint on a line that never reached ``line_map`` (rare —
    most arithmetic statements map to at least one C line) is still reported.
    """
    hints_by_line = collect_hints(python_source)

    # Attach the per-line list to every mapped line (empty list when none).
    for py_line, mapping in line_map.items():
        mapping["strength_hints"] = hints_by_line.get(py_line, [])

    totals: Dict[str, int] = {}
    flat: List[dict] = []
    for py_line, hints in hints_by_line.items():
        for h in hints:
            totals[h["kind"]] = totals.get(h["kind"], 0) + 1
            flat.append({"py_line": py_line, "kind": h["kind"], "message": h["message"]})

    hint_totals = {
        kind: totals[kind]
        for kind in sorted(totals, key=lambda k: _KIND_ORDER.get(k, 99))
    }
    flat.sort(key=lambda h: (h["py_line"], _KIND_ORDER.get(h["kind"], 99)))
    return {"hint_totals": hint_totals, "hints": flat}
