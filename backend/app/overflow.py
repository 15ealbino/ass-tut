"""
Integer-overflow risk hints — a source-level companion to the asm-scan passes.

Where :mod:`app.strength` teaches *which arithmetic the compiler rewrites*, this
pass teaches a correctness/security gap that the Python→C→asm pipeline silently
introduces: **Python integers are arbitrary precision; the C ``int`` this
transpiler emits is a fixed 32-bit value.** Every Python ``int`` becomes a plain
C ``int`` (see ``transpiler.py`` — ``int`` is the only integer type it emits),
and gcc targets ``-m32``, so that ``int`` is a 32-bit signed value whose range is
``-2_147_483_648 .. 2_147_483_647`` (``INT_MAX`` == ``2147483647``).

The teachable, dangerous fact (mission pillar 2 — spot the *bug behind the
assembly*):

  * A multiply of two runtime values (``area = w * h``, ``n * n``) compiles to a
    32-bit ``imul`` whose product **silently wraps** once it passes ``INT_MAX``.
    In Python the same expression keeps growing; in the emitted C it overflows —
    signed overflow is *undefined behaviour* in C, and at ``-O0`` wraps modulo
    2**32 in practice. This is the canonical size-calculation overflow (CWE-190),
    the root of countless ``malloc(count * size)`` heap bugs.
  * An in-place multiply inside a loop (``fact *= i`` — a factorial / power
    accumulator) overflows a 32-bit ``int`` *astonishingly* fast: ``13!`` already
    exceeds ``INT_MAX``. Python prints the exact big integer; the C version wraps.

Both point the learner straight at the ``imul`` their line became — pillar 1 (a
concrete Python→asm anchor) and pillar 2 (the bug that anchor hides).

Scope (deliberately tight, mirroring ``strength.py``'s quiet-signal design):

  * Only **multiplication** is flagged — the operation whose result grows fastest
    and the overwhelmingly common overflow site. Addition / subtraction overflow
    is real but needs operands already near ``INT_MAX``; flagging every ``+``
    would drown the signal, so it is intentionally out of scope.
  * ``mul-overflow`` fires only when **both** operands are non-literal (a genuine
    unknown × unknown). A multiply by a literal (``a * 8``) is left to the
    strength pass — multiplying by a small constant rarely overflows and would
    just be noise here.
  * ``mul-accumulate`` fires only for an augmented ``*=`` **inside a loop** — the
    accumulator pattern that overflows under repetition. A one-off ``x *= 2`` at
    top level is not flagged.

Risks are derived from the AST, not the assembly, so they are stable across gcc
versions and never fire on a folded constant expression (``1000 * 1000``), where
both operands are literals and no runtime overflow can arise.
"""
import ast
from typing import Dict, List, Optional, Tuple

# Largest value a 32-bit signed C ``int`` can hold (the transpiler's integer type
# under gcc ``-m32``). Named once here so the teaching messages stay consistent.
INT_MAX = 2_147_483_647

# ── Risk kinds ───────────────────────────────────────────────────────────────
#
# Two kinds, ordered for a stable per-line and summary listing. The message is
# the teaching payload; the kind is the stable machine-readable label the
# frontend groups / marks by.
KIND_MUL_OVERFLOW = "mul-overflow"      # a * b  (two runtime operands → 32-bit imul can wrap)
KIND_MUL_ACCUMULATE = "mul-accumulate"  # x *= … inside a loop (accumulator overflows fast)

# Stable display / serialisation order (mirrors the ordered maps in app.strength).
_KIND_ORDER = {KIND_MUL_OVERFLOW: 0, KIND_MUL_ACCUMULATE: 1}

_MSG_MUL_OVERFLOW = (
    "Multiplying two runtime values compiles to a 32-bit `imul`. Python integers "
    "are arbitrary precision, but this transpiler emits a C `int`, which gcc "
    f"targets as 32-bit signed — its range stops at INT_MAX ({INT_MAX:,}). A "
    "product above that silently wraps (signed overflow is undefined behaviour in "
    "C; at -O0 it wraps modulo 2**32). This is the classic size-calculation "
    "overflow (CWE-190); look at the `imul` on this line — its result is "
    "truncated to 32 bits, so the asm can disagree with what Python would print."
)

_MSG_MUL_ACCUMULATE = (
    "Repeated in-place multiplication inside a loop (a factorial / power "
    "accumulator) overflows a 32-bit `int` very fast — `13!` alone already "
    f"exceeds INT_MAX ({INT_MAX:,}). Python keeps the exact big integer; the C "
    "`int` here wraps (signed overflow is undefined behaviour in C). Watch the "
    "loop's `imul` feed a value that silently truncates once the running product "
    "passes 2**31 — the asm result diverges from Python with no error raised."
)


def _is_literal(node: ast.expr) -> bool:
    """True if ``node`` is a compile-time integer literal, including a negated one.

    A bare ``ast.Constant`` (``4``) is a literal; so is a unary ``+``/``-`` on a
    constant (``-4``), which the parser represents as ``UnaryOp(USub, Constant)``
    rather than a single ``Constant``. Treating the negated form as a literal too
    keeps ``mul-overflow`` from mis-firing on ``a * -4`` (a constant multiply, not
    an unknown × unknown). Folded constant-only expressions are thus skipped — no
    runtime overflow can arise where both operands are known at compile time.
    """
    if isinstance(node, ast.Constant):
        return True
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, (ast.USub, ast.UAdd))
        and isinstance(node.operand, ast.Constant)
    ):
        return True
    return False


def risk_for_binop(node: ast.BinOp) -> Optional[Tuple[str, str]]:
    """Return ``(kind, message)`` for a single binary-operation node, or ``None``.

    Pure and side-effect free so it can be unit-tested without gcc or the AST
    walk. The one rule: a ``Mult`` whose **both** operands are non-literal (a
    genuine runtime × runtime product) → ``mul-overflow``. Anything else — a
    non-multiply op, or a multiply where either operand is a literal (``a * 8``,
    ``1000 * 1000``) — returns ``None``, leaving constant-scaled multiplies to the
    strength pass and folded constants unflagged.
    """
    if not isinstance(node.op, ast.Mult):
        return None
    if _is_literal(node.left) or _is_literal(node.right):
        return None
    return (KIND_MUL_OVERFLOW, _MSG_MUL_OVERFLOW)


class _RiskCollector(ast.NodeVisitor):
    """Walk the tree tracking loop nesting, recording overflow risks per line.

    Two node kinds are inspected:

      * ``BinOp`` → classified by :func:`risk_for_binop` (``mul-overflow``),
        regardless of loop context — an unknown × unknown product is a risk
        anywhere.
      * ``AugAssign`` with a ``Mult`` op (``x *= …``) → ``mul-accumulate``, but
        **only inside a loop**: the accumulator pattern overflows under
        repetition, while a one-off ``*=`` at top level is not a bug.

    Children are always visited (``generic_visit``) so nested arithmetic and the
    right-hand side of an augmented assignment are reached too — a line like
    ``x *= a * b`` records both an accumulate risk and the inner mul-overflow.
    """

    def __init__(self) -> None:
        # line -> {kind: message}, preserving the first-seen message per
        # (line, kind) so repeated hits of one kind on a line stay a single entry.
        self.per_line: Dict[int, Dict[str, str]] = {}
        self._loop_depth = 0

    def _record(self, line: Optional[int], kind: str, message: str) -> None:
        if line is None:
            return
        self.per_line.setdefault(line, {}).setdefault(kind, message)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A function body has its own loop context: a loop *around* the def does
        # not make the body's statements run repeatedly. Reset the depth for the
        # duration of the body so a `*=` there is judged by its own loops only.
        saved, self._loop_depth = self._loop_depth, 0
        self.generic_visit(node)
        self._loop_depth = saved

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_BinOp(self, node: ast.BinOp) -> None:
        risk = risk_for_binop(node)
        if risk is not None:
            self._record(getattr(node, "lineno", None), risk[0], risk[1])
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.op, ast.Mult) and self._loop_depth > 0:
            self._record(getattr(node, "lineno", None), KIND_MUL_ACCUMULATE, _MSG_MUL_ACCUMULATE)
        self.generic_visit(node)


def collect_overflow_risks(python_source: str) -> Dict[int, List[dict]]:
    """Walk ``python_source`` and return ``{py_lineno: [ {kind, message}, ... ]}``.

    Every multiplication is classified (see :class:`_RiskCollector`). Multiple
    hits of the *same kind* on one line are de-duplicated (``a*b + c*d`` reports a
    single ``mul-overflow``, keeping the first message) so the signal stays quiet;
    distinct kinds on one line are all kept, ordered by ``_KIND_ORDER``.

    A syntax error yields an empty map rather than raising — defensive only, since
    this runs after a successful transpile whose parse has already succeeded.
    """
    try:
        tree = ast.parse(python_source)
    except SyntaxError:
        return {}

    collector = _RiskCollector()
    collector.visit(tree)

    result: Dict[int, List[dict]] = {}
    for line, kinds in collector.per_line.items():
        ordered = sorted(kinds.items(), key=lambda kv: _KIND_ORDER.get(kv[0], 99))
        result[line] = [{"kind": k, "message": m} for k, m in ordered]
    return result


def analyze_overflow(
    line_map: Dict[int, dict],
    python_source: str,
) -> dict:
    """Annotate each ``line_map`` entry with an ``overflow_hints`` list and return
    a program-wide summary. Mutates ``line_map`` in place.

    Like :func:`app.strength.analyze_strength`, this pass keys off the Python
    source line number (the ``line_map`` key), so it needs no assembly. Every
    mapped line receives an ``overflow_hints`` list (empty when the line has no
    flagged multiplication), mirroring how the other passes always attach their
    field.

    The returned summary is::

        {
          "risk_totals": {kind: number_of_lines_with_that_kind, ...},  # ordered
          "risks":       [{"py_line": n, "kind": k, "message": m}, ...],
        }

    ``risk_totals`` omits zero entries and is ordered by kind; ``risks`` is
    ordered by ``(py_line, kind)``. The summary is built from every flagged line
    in the source, so a risk on a line that never reached ``line_map`` (rare) is
    still reported.
    """
    risks_by_line = collect_overflow_risks(python_source)

    # Attach the per-line list to every mapped line (empty list when none).
    for py_line, mapping in line_map.items():
        mapping["overflow_hints"] = risks_by_line.get(py_line, [])

    totals: Dict[str, int] = {}
    flat: List[dict] = []
    for py_line, risks in risks_by_line.items():
        for r in risks:
            totals[r["kind"]] = totals.get(r["kind"], 0) + 1
            flat.append({"py_line": py_line, "kind": r["kind"], "message": r["message"]})

    risk_totals = {
        kind: totals[kind]
        for kind in sorted(totals, key=lambda k: _KIND_ORDER.get(k, 99))
    }
    flat.sort(key=lambda r: (r["py_line"], _KIND_ORDER.get(r["kind"], 99)))
    return {"risk_totals": risk_totals, "risks": flat}
