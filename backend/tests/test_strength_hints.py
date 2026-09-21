"""
Tests for the arithmetic-strength-hints feature (feat/arith-strength-hints).

Where the cost / mix / memory passes describe the *assembly* a Python line
compiled to, strength hints describe it from the source end: they teach which
arithmetic the compiler strength-reduces and which it cannot. Verified against
the app's real build (`gcc -O0 -m32`):

  * `a * 8`  → a left shift `sal $3` (never an `imul`);
  * `n // 4` → an arithmetic shift `sar` + a sign fixup (never an `idiv`);
  * `n % 8`  → shifts + a bitwise `and $7` (never an `idiv`);
  * `a / b`  → a real, costly `idiv` (a runtime divisor cannot be reduced).

Two layers, mirroring test_memory_traffic.py / test_register_footprint.py:
  * Pure-function unit tests for `hint_for_binop` / `collect_hints` /
    `analyze_strength` — no gcc, no assembly needed (the pass is source-driven).
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert both that the summary reaches the API and that the asm the hint
    describes is actually what gcc emits.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import ast
import shutil
import subprocess

import pytest

from app.strength import (
    KIND_DIV_POW2,
    KIND_DIV_VAR,
    KIND_MUL_POW2,
    analyze_strength,
    collect_hints,
    hint_for_binop,
)

# asyncio_mode=auto (pytest.ini) auto-detects the async e2e tests; the sync unit
# tests below need no marker.


# ─── gcc availability guard (mirrors the real pipeline's requirements) ───────

def _gcc_m32_available() -> bool:
    if shutil.which("gcc") is None:
        return False
    try:
        r = subprocess.run(
            ["gcc", "-S", "-O0", "-m32", "-x", "c", "-o", "/dev/null", "-"],
            input='#include <stdio.h>\nint main(){printf("");return 0;}',
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


needs_gcc = pytest.mark.skipif(
    not _gcc_m32_available(), reason="gcc with -m32 support not available"
)


# ─── Unit: hint_for_binop (pure, no gcc) ─────────────────────────────────────

def _binop(expr: str) -> ast.BinOp:
    """Parse a single expression string into its top-level BinOp node."""
    node = ast.parse(expr, mode="eval").body
    assert isinstance(node, ast.BinOp), f"{expr!r} is not a BinOp"
    return node


@pytest.mark.parametrize(
    "expr,kind",
    [
        # ── multiply by a power of two, either operand order ──
        ("a * 8", KIND_MUL_POW2),
        ("8 * a", KIND_MUL_POW2),
        ("a * 2", KIND_MUL_POW2),        # smallest hinted power (2**1)
        ("count * 1024", KIND_MUL_POW2),
        # ── divide / floor-divide / modulo by a power of two ──
        ("n / 4", KIND_DIV_POW2),
        ("n // 4", KIND_DIV_POW2),
        ("n % 8", KIND_DIV_POW2),
        ("total // 2", KIND_DIV_POW2),
        # ── a genuine idiv: the divisor is a runtime value ──
        ("a / b", KIND_DIV_VAR),
        ("a // b", KIND_DIV_VAR),
        ("a % b", KIND_DIV_VAR),
        ("total // count", KIND_DIV_VAR),
    ],
)
def test_hint_for_binop_fires(expr, kind):
    hint = hint_for_binop(_binop(expr))
    assert hint is not None, f"expected a hint for {expr!r}"
    assert hint[0] == kind
    assert hint[1] and isinstance(hint[1], str)


@pytest.mark.parametrize(
    "expr",
    [
        # ── constant/constant expressions: folded at compile time, no asm ──
        "2 * 3",
        "8 * 4",
        "16 // 4",
        "7 // 3",
        "10 % 4",
        # ── multiplication that is not by a power of two ──
        "a * 6",
        "a * 3",
        "a * b",
        # ── non-power-of-two CONSTANT divisor: gcc uses a magic multiply, not a
        #    clean shift and not an idiv, so it is deliberately left un-hinted ──
        "n // 3",
        "n % 10",
        "x % 7",
        # ── multiply/divide by one (2**0) is a no-op the front end drops ──
        "a * 1",
        "n // 1",
        # ── non-arithmetic / unrelated operators ──
        "a + b",
        "a - b",
        "a << 2",
        "a & 7",
    ],
)
def test_hint_for_binop_silent(expr):
    assert hint_for_binop(_binop(expr)) is None


def test_hint_for_binop_boolean_operand_is_not_a_power_of_two():
    # `True` is an int subclass (== 1) but must never be read as a power-of-two
    # factor; `a // False` has a constant (non-pow2) divisor, so no hint.
    assert hint_for_binop(_binop("a * True")) is None
    assert hint_for_binop(_binop("a // False")) is None


def test_mul_pow2_message_names_the_shift_not_imul():
    _, message = hint_for_binop(_binop("a * 8"))
    assert "sal $3" in message          # 8 == 2**3
    assert "no `imul`" in message


def test_div_pow2_message_names_shift_and_bitwise_and():
    _, message = hint_for_binop(_binop("n % 8"))
    assert "sar" in message
    assert "and $7" in message          # % 8 -> & 7
    assert "no `idiv`" in message


def test_div_var_message_names_idiv():
    _, message = hint_for_binop(_binop("a / b"))
    assert "idiv" in message


# ─── Unit: collect_hints (pure, no gcc) ──────────────────────────────────────

def test_collect_hints_attributes_to_source_lines():
    src = "x = a * 8\ny = n // 4\nz = p % q\n"
    hints = collect_hints(src)
    assert hints[1][0]["kind"] == KIND_MUL_POW2
    assert hints[2][0]["kind"] == KIND_DIV_POW2
    assert hints[3][0]["kind"] == KIND_DIV_VAR


def test_collect_hints_dedupes_same_kind_per_line():
    # Two power-of-two multiplies on one line collapse to a single mul-pow2 entry
    # so the signal stays quiet.
    hints = collect_hints("w = a * 8 + b * 4\n")
    assert len(hints[1]) == 1
    assert hints[1][0]["kind"] == KIND_MUL_POW2


def test_collect_hints_keeps_distinct_kinds_on_one_line_in_order():
    # A line with both a pow2 multiply and a runtime divide keeps both, ordered
    # mul-pow2 before div-var.
    hints = collect_hints("r = a * 16 + b / c\n")
    kinds = [h["kind"] for h in hints[1]]
    assert kinds == [KIND_MUL_POW2, KIND_DIV_VAR]


def test_collect_hints_finds_arithmetic_inside_nested_constructs():
    # The walk is over the whole tree, so arithmetic inside a loop / function
    # body is flagged at its own line.
    src = "def f(n):\n    for i in range(n):\n        y = i * 8\n    return y\n"
    hints = collect_hints(src)
    assert 3 in hints
    assert hints[3][0]["kind"] == KIND_MUL_POW2


def test_collect_hints_empty_for_no_arithmetic():
    assert collect_hints("x = 1\nprint(x)\n") == {}


def test_collect_hints_syntax_error_returns_empty():
    # Defensive: a parse failure yields no hints rather than raising.
    assert collect_hints("def (:\n") == {}


# ─── Unit: analyze_strength (pure, no gcc) ───────────────────────────────────

def _line_map(*linenos):
    return {n: {"c_lines": [n], "asm_lines": [], "color": "#000"} for n in linenos}


def test_analyze_strength_annotates_line_map_and_summary():
    src = "x = a * 8\ny = n // 4\n"
    line_map = _line_map(1, 2)
    summary = analyze_strength(line_map, src)

    # Per-line annotation.
    assert line_map[1]["strength_hints"][0]["kind"] == KIND_MUL_POW2
    assert line_map[2]["strength_hints"][0]["kind"] == KIND_DIV_POW2
    # Program-wide summary.
    assert summary["hint_totals"] == {KIND_MUL_POW2: 1, KIND_DIV_POW2: 1}
    assert [h["py_line"] for h in summary["hints"]] == [1, 2]


def test_analyze_strength_unflagged_lines_get_empty_list():
    # Every mapped line gets a strength_hints list, empty when nothing fires —
    # mirroring how the memory pass always attaches memory_counts.
    line_map = _line_map(1, 2)
    analyze_strength(line_map, "x = 1\ny = x + 2\n")
    assert line_map[1]["strength_hints"] == []
    assert line_map[2]["strength_hints"] == []


def test_analyze_strength_hint_totals_ordered_and_zero_omitted():
    src = "a = x * 8\nb = y * 4\nc = z / w\n"
    summary = analyze_strength(_line_map(1, 2, 3), src)
    # mul-pow2 counted twice, div-var once, div-pow2 absent (omitted, not zero).
    assert list(summary["hint_totals"].items()) == [
        (KIND_MUL_POW2, 2),
        (KIND_DIV_VAR, 1),
    ]


def test_analyze_strength_does_not_disturb_existing_fields():
    # Regression: the pass only adds strength_hints, leaving prior annotations
    # (here a memory_counts placeholder) untouched.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000",
                    "memory_counts": {"loads": 1}}}
    analyze_strength(line_map, "x = a * 8\n")
    assert line_map[1]["memory_counts"] == {"loads": 1}
    assert line_map[1]["strength_hints"][0]["kind"] == KIND_MUL_POW2


def test_analyze_strength_empty_line_map():
    summary = analyze_strength({}, "x = a * 8\n")
    # No mapped lines to annotate, but the source-level summary still reports it.
    assert summary["hint_totals"] == {KIND_MUL_POW2: 1}
    assert summary["hints"][0]["py_line"] == 1


# ─── End-to-end: /compile carries the strength summary + matches real asm ────

def _asm_for_line(body: dict, py_line: str) -> str:
    """Join the display-asm text lines that a Python line maps to."""
    mapping = body["line_map"][py_line]
    return "\n".join(body["asm_lines"][i - 1] for i in mapping["asm_lines"])


@needs_gcc
async def test_compile_response_includes_strength_summary(client):
    r = await client.post("/compile", json={"code": "a = 5\nb = a * 8\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["strength_summary"] is not None
    totals = body["strength_summary"]["hint_totals"]
    assert totals.get(KIND_MUL_POW2) == 1
    # The flagged line carries the hint inline too.
    assert body["line_map"]["2"]["strength_hints"][0]["kind"] == KIND_MUL_POW2
    # Every mapped line exposes a strength_hints list (empty where nothing fires).
    for mapping in body["line_map"].values():
        assert "strength_hints" in mapping
        assert isinstance(mapping["strength_hints"], list)


@needs_gcc
async def test_compile_pow2_multiply_is_a_shift_not_imul(client):
    # Ground the hint in reality: the mul-pow2 line must actually compile to a
    # left shift and NOT an imul — exactly what the hint claims.
    r = await client.post("/compile", json={"code": "a = 5\nb = a * 8\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["2"]["strength_hints"][0]["kind"] == KIND_MUL_POW2
    asm = _asm_for_line(body, "2")
    assert "sal" in asm or "shl" in asm
    assert "imul" not in asm
    # The cost pass agrees there is no expensive multiply flag on this line.
    assert "mul" not in body["line_map"]["2"]["flags"]


@needs_gcc
async def test_compile_pow2_division_is_a_shift_not_idiv(client):
    # A power-of-two divide is strength-reduced to shifts — no idiv.
    r = await client.post("/compile", json={"code": "a = 40\nb = a // 4\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["2"]["strength_hints"][0]["kind"] == KIND_DIV_POW2
    asm = _asm_for_line(body, "2")
    assert "sar" in asm or "shr" in asm
    assert "idiv" not in asm
    assert "div" not in body["line_map"]["2"]["flags"]


@needs_gcc
async def test_compile_variable_division_really_emits_idiv(client):
    # A runtime divisor is the one case the compiler cannot reduce: a real idiv,
    # matching the div-var hint and the cost pass's "div" flag.
    r = await client.post("/compile", json={"code": "a = 20\nb = 3\nc = a // b\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["3"]["strength_hints"][0]["kind"] == KIND_DIV_VAR
    asm = _asm_for_line(body, "3")
    assert "idiv" in asm
    assert "div" in body["line_map"]["3"]["flags"]


@needs_gcc
async def test_compile_no_arithmetic_has_empty_strength_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\nprint(x)\n"})
    assert r.status_code == 200
    summary = r.json()["strength_summary"]
    assert summary["hint_totals"] == {}
    assert summary["hints"] == []
