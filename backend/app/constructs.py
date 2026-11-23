"""
Construct map — what each Python line *is*, and the asm shape it lowers to.

Every other per-line pass in ``app.compile`` works from the far end of the
pipeline, scanning the generated *assembly*: the instruction mix, register
footprint, stack frame map, memory traffic, branch maps, addressing modes and
immediate values all read ``mapping["asm_lines"]``. This pass works from the
near end — the Python AST — and answers the most elementary question of all,
the one a learner asks before any asm detail: **what kind of statement is this
line, and what shape of machine code does that kind become?**

It classifies each mapped Python line into one construct kind — an assignment,
an augmented assignment, a ``for``/``while`` loop header, an ``if``/``elif``, a
``def``, a ``return``, a ``break``/``continue``, a call statement, an import,
and so on — the supported subset the transpiler accepts (see CLAUDE.md).

The lesson this teaches (mission pillar 1 — make the Python → C → x86 mapping
concrete, with a direct bridge to pillar 2's control-flow reading):

  * Each construct lowers to a *recognisable* asm shape, and naming the
    construct points the eye straight at that shape in the ASM pane. A ``for``
    becomes a **backward** conditional jump (the loop back-edge); an ``if``
    becomes a **forward** conditional jump around its body (the branch-around);
    a ``def`` becomes a prologue/epilogue (``push %ebp`` … ``leave; ret``); a
    ``return`` loads ``%eax`` then returns; a ``break`` is an unconditional jump
    out of the loop. Reading those shapes off a disassembly — loop = backward
    branch, if/else = forward-around — is a day-one reverse-engineering skill,
    and the construct map is the Rosetta stone that pairs each Python keyword
    with the shape it produces.
  * The per-program tally ("3 assign · 1 for · 1 if") is a one-glance summary of
    the code's *structure*, the scaffolding every other per-line pass hangs its
    numbers on.

Classification is derived from the AST, not the assembly, so it needs no gcc and
is stable across toolchains (the same property the arithmetic strength-hint pass
relies on). The presentation strings — the human label for each kind and the
one-line asm-shape hint — live in the frontend, next to the other passes'
presentation maps; the API carries only the compact machine-readable kind.
"""
import ast
from typing import Dict

# ── Construct kinds ──────────────────────────────────────────────────────────
#
# Stable machine-readable kind per supported statement type, plus a display
# order (mirrors the ordered maps in app.compile): definitions first, then the
# data statements, then control flow, then calls / imports / bare expressions.
KIND_FUNCDEF = "funcdef"
KIND_CLASSDEF = "classdef"
KIND_ASSIGN = "assign"
KIND_AUGASSIGN = "augassign"
KIND_FOR = "for"
KIND_WHILE = "while"
KIND_IF = "if"
KIND_CALL = "call"
KIND_RETURN = "return"
KIND_BREAK = "break"
KIND_CONTINUE = "continue"
KIND_IMPORT = "import"
KIND_EXPR = "expr"

_CONSTRUCT_ORDER: Dict[str, int] = {
    KIND_FUNCDEF: 0,
    KIND_CLASSDEF: 1,
    KIND_ASSIGN: 2,
    KIND_AUGASSIGN: 3,
    KIND_FOR: 4,
    KIND_WHILE: 5,
    KIND_IF: 6,
    KIND_CALL: 7,
    KIND_RETURN: 8,
    KIND_BREAK: 9,
    KIND_CONTINUE: 10,
    KIND_IMPORT: 11,
    KIND_EXPR: 12,
}


def classify_statement(node: ast.AST) -> str | None:
    """Classify one AST *statement* node into its construct kind, or ``None`` if
    it is not a statement this pass names.

    Pure and side-effect free so it can be unit-tested without gcc or the AST
    walk. The mapping follows the transpiler's supported subset:

    * ``def`` / ``async def``        → ``"funcdef"``
    * ``class``                      → ``"classdef"``
    * ``x = …``                      → ``"assign"``
    * ``x += …`` (augmented)         → ``"augassign"``
    * ``for … in …`` / ``async for`` → ``"for"``
    * ``while …``                    → ``"while"``
    * ``if …`` / ``elif …``          → ``"if"`` (an ``elif`` is an ``If`` node in
                                       the parent's ``orelse``, with its own line)
    * ``return …``                   → ``"return"``
    * ``break``                      → ``"break"``
    * ``continue``                   → ``"continue"``
    * ``import`` / ``from … import`` → ``"import"``
    * a bare expression statement    → ``"call"`` if it is a call (``print(x)``),
                                       else ``"expr"``

    Anything else (an annotated assignment with no value, a ``pass``, a ``with``,
    …) returns ``None`` and is left unclassified rather than mis-labelled.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return KIND_FUNCDEF
    if isinstance(node, ast.ClassDef):
        return KIND_CLASSDEF
    if isinstance(node, ast.Assign):
        return KIND_ASSIGN
    if isinstance(node, ast.AugAssign):
        return KIND_AUGASSIGN
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return KIND_FOR
    if isinstance(node, ast.While):
        return KIND_WHILE
    if isinstance(node, ast.If):
        return KIND_IF
    if isinstance(node, ast.Return):
        return KIND_RETURN
    if isinstance(node, ast.Break):
        return KIND_BREAK
    if isinstance(node, ast.Continue):
        return KIND_CONTINUE
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return KIND_IMPORT
    if isinstance(node, ast.Expr):
        # A bare expression statement. The only one the transpiler emits code for
        # is a call (notably print()); distinguish it so the common case reads as
        # "call" rather than a generic "expr".
        return KIND_CALL if isinstance(node.value, ast.Call) else KIND_EXPR
    return None


def collect_constructs(python_source: str) -> Dict[int, str]:
    """Walk ``python_source`` and return ``{py_lineno: construct_kind}``.

    Every statement node is classified by :func:`classify_statement` and
    attributed to its header line (``node.lineno``). When two statements share a
    line (``a = 1; b = 2``), the first seen wins, so a line maps to exactly one
    kind. Non-statement nodes (expressions, operators) are skipped — only the
    statement a line *is* gets a kind, never the sub-expressions inside it.

    A syntax error yields an empty map rather than raising — defensive only,
    since this runs after a successful transpile whose parse already succeeded.
    """
    try:
        tree = ast.parse(python_source)
    except SyntaxError:
        return {}

    per_line: Dict[int, str] = {}
    for node in ast.walk(tree):
        kind = classify_statement(node)
        if kind is None:
            continue
        line = getattr(node, "lineno", None)
        if line is None:
            continue
        per_line.setdefault(line, kind)
    return per_line


def _ordered_construct_map(counts: Dict[str, int]) -> Dict[str, int]:
    """Return ``counts`` with zero entries dropped and keys in display order."""
    return {
        kind: counts[kind]
        for kind in sorted(counts, key=lambda k: _CONSTRUCT_ORDER.get(k, 99))
        if counts[kind] > 0
    }


def analyze_constructs(
    line_map: Dict[int, dict],
    python_source: str,
) -> dict:
    """Annotate each ``line_map`` entry with a ``construct`` kind and return a
    program-wide summary. Mutates ``line_map`` in place.

    Like the arithmetic strength-hint pass (and unlike the asm-scan passes), this
    keys off the Python source line number — the ``line_map`` dict key — so it
    needs no assembly. Every mapped line receives a ``construct_kind`` string,
    empty (``""``) when the line is not one of the named statement kinds,
    mirroring how the other passes always attach their field.

    The returned summary is::

        {"construct_totals": {kind: number_of_mapped_lines, ...}}  # ordered

    ``construct_totals`` counts the MAPPED Python lines of each kind (so it is the
    structural shape of exactly the code shown in the panes), omits zero entries,
    and is ordered by ``_CONSTRUCT_ORDER``.
    """
    constructs_by_line = collect_constructs(python_source)

    totals: Dict[str, int] = {}
    for py_line, mapping in line_map.items():
        kind = constructs_by_line.get(py_line, "")
        mapping["construct_kind"] = kind
        if kind:
            totals[kind] = totals.get(kind, 0) + 1

    return {"construct_totals": _ordered_construct_map(totals)}
