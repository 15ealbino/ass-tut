"""
Tests for the integer-overflow-risk-hints feature (feat/int-overflow-hints).

Where the strength pass describes the *cost* of a Python line's arithmetic (which
multiply/divide the compiler rewrites), the overflow pass describes a
*correctness/security* gap: Python integers are arbitrary precision, but this
transpiler emits a C `int`, which gcc targets as a 32-bit signed value
(INT_MAX == 2,147,483,647). A multiplication whose product passes INT_MAX
silently wraps in the emitted C/asm while Python would keep the exact big
integer — the classic CWE-190 overflow, pointing straight at the line's `imul`.

Two kinds are flagged:
  * mul-overflow   — a binary `*` of two runtime operands (`w * h`, `n * n`);
  * mul-accumulate — an in-place `*=` inside a loop (a `fact *= i` accumulator).

Two layers, mirroring test_strength_hints.py:
  * Pure-function unit tests for `risk_for_binop` / `collect_overflow_risks` /
    `analyze_overflow` — no gcc, no assembly needed (the pass is source-driven).
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert both that the summary reaches the API and that the asm the hint
    describes (an `imul`) is actually what gcc emits.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import ast
import shutil
import subprocess

import pytest

from app.overflow import (
    INT_MAX,
    KIND_MUL_ACCUMULATE,
    KIND_MUL_OVERFLOW,
    analyze_overflow,
    collect_overflow_risks,
    risk_for_binop,
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


# ─── Unit: risk_for_binop (pure, no gcc) ─────────────────────────────────────

def _binop(expr: str) -> ast.BinOp:
    """Parse a single expression string into its top-level BinOp node."""
    node = ast.parse(expr, mode="eval").body
    assert isinstance(node, ast.BinOp), f"{expr!r} is not a BinOp"
    return node


@pytest.mark.parametrize(
    "expr",
    [
        # ── two runtime operands: a genuine unknown × unknown product ──
        "a * b",
        "w * h",
        "n * n",            # a square — overflows fast, same name both sides
        "total * count",
        "price * qty",
        "f(x) * g(y)",      # calls are runtime values, not literals
        "xs[i] * xs[j]",    # subscripts are runtime values
    ],
)
def test_risk_for_binop_fires_on_runtime_product(expr):
    risk = risk_for_binop(_binop(expr))
    assert risk is not None, f"expected a risk for {expr!r}"
    assert risk[0] == KIND_MUL_OVERFLOW
    assert risk[1] and isinstance(risk[1], str)


@pytest.mark.parametrize(
    "expr",
    [
        # ── a literal operand: left to the strength pass, not an overflow risk
        #    here (multiplying by a small constant rarely overflows) ──
        "a * 8",
        "8 * a",
        "a * 2",
        "count * 1024",
        "a * -4",           # a NEGATED literal is still a literal (not unknown)
        "a * +4",
        # ── both operands literal: folded at compile time, no runtime overflow ──
        "2 * 3",
        "1000 * 1000",
        "-5 * 6",
        # ── not a multiplication at all ──
        "a + b",
        "a - b",
        "a / b",
        "a // b",
        "a % b",
    ],
)
def test_risk_for_binop_silent(expr):
    assert risk_for_binop(_binop(expr)) is None


def test_mul_overflow_message_names_imul_and_int_max():
    _, message = risk_for_binop(_binop("w * h"))
    assert "imul" in message
    assert f"{INT_MAX:,}" in message        # 2,147,483,647
    assert "CWE-190" in message


# ─── Unit: collect_overflow_risks (pure, no gcc) ─────────────────────────────

def test_collect_attributes_runtime_product_to_its_line():
    src = "a = 3\nb = 4\nc = a * b\n"
    risks = collect_overflow_risks(src)
    assert risks[3][0]["kind"] == KIND_MUL_OVERFLOW
    # Non-multiply lines are not flagged.
    assert 1 not in risks and 2 not in risks


def test_collect_accumulate_fires_inside_a_for_loop():
    src = "fact = 1\nfor i in range(20):\n    fact *= i\n"
    risks = collect_overflow_risks(src)
    assert risks[3][0]["kind"] == KIND_MUL_ACCUMULATE


def test_collect_accumulate_fires_inside_a_while_loop():
    src = "p = 1\nn = 0\nwhile n < 40:\n    p *= 2\n    n += 1\n"
    risks = collect_overflow_risks(src)
    assert risks[4][0]["kind"] == KIND_MUL_ACCUMULATE


def test_collect_accumulate_silent_outside_a_loop():
    # A one-off `*=` at top level is not the overflowing accumulator pattern.
    assert collect_overflow_risks("x = 7\nx *= 2\n") == {}


def test_collect_accumulate_only_for_mult_op():
    # `+=` / `-=` inside a loop are not multiplication, so no overflow risk fires.
    src = "s = 0\nfor i in range(10):\n    s += i\n    s -= 1\n"
    assert collect_overflow_risks(src) == {}


def test_collect_loop_depth_resets_after_the_loop():
    # The `*=` on line 3 is inside the loop (fires); the one on line 4 is after
    # it (top level, silent) — loop depth must drop back to zero on loop exit.
    src = "x = 1\nfor i in range(5):\n    x *= i\nx *= 2\n"
    risks = collect_overflow_risks(src)
    assert risks[3][0]["kind"] == KIND_MUL_ACCUMULATE
    assert 4 not in risks


def test_collect_dedupes_same_kind_per_line():
    # Two runtime products on one line collapse to a single mul-overflow entry.
    risks = collect_overflow_risks("z = a * b + c * d\n")
    assert len(risks[1]) == 1
    assert risks[1][0]["kind"] == KIND_MUL_OVERFLOW


def test_collect_keeps_distinct_kinds_on_one_line_in_order():
    # `x *= a * b` inside a loop is BOTH an accumulator (`*=`) and a runtime
    # product (`a * b`); both kinds are kept, ordered mul-overflow before
    # mul-accumulate.
    src = "x = 1\nfor i in range(3):\n    x *= a * b\n"
    kinds = [r["kind"] for r in collect_overflow_risks(src)[3]]
    assert kinds == [KIND_MUL_OVERFLOW, KIND_MUL_ACCUMULATE]


def test_collect_accumulate_inside_loop_in_function_fires():
    # The common factorial shape: a `*=` in a loop inside a function body.
    src = "def fact(n):\n    f = 1\n    for i in range(1, n):\n        f *= i\n    return f\n"
    risks = collect_overflow_risks(src)
    assert risks[4][0]["kind"] == KIND_MUL_ACCUMULATE


def test_collect_function_body_resets_loop_context():
    # A `def` nested inside a loop must NOT inherit that loop's context: the
    # function's own body runs per-call, not per-iteration. The `*=` on line 3
    # has no loop of its own, so it is not an accumulator.
    src = "for _ in range(5):\n    def g():\n        y *= 2\n"
    assert collect_overflow_risks(src) == {}


def test_collect_finds_product_nested_in_constructs():
    # The walk covers the whole tree: a product inside a function / loop body is
    # flagged at its own line.
    src = "def area(w, h):\n    for _ in range(1):\n        a = w * h\n    return a\n"
    risks = collect_overflow_risks(src)
    assert risks[3][0]["kind"] == KIND_MUL_OVERFLOW


def test_collect_empty_for_no_multiplication():
    assert collect_overflow_risks("x = 1\ny = x + 2\nprint(y)\n") == {}


def test_collect_constant_product_is_not_flagged():
    # A fully constant product is folded by gcc; no runtime overflow can arise.
    assert collect_overflow_risks("x = 1000 * 1000\n") == {}


def test_collect_syntax_error_returns_empty():
    # Defensive: a parse failure yields no risks rather than raising.
    assert collect_overflow_risks("def (:\n") == {}


# ─── Unit: analyze_overflow (pure, no gcc) ───────────────────────────────────

def _line_map(*linenos):
    return {n: {"c_lines": [n], "asm_lines": [], "color": "#000"} for n in linenos}


def test_analyze_annotates_line_map_and_summary():
    src = "w = 3\nh = 4\na = w * h\n"
    line_map = _line_map(1, 2, 3)
    summary = analyze_overflow(line_map, src)

    # Per-line annotation.
    assert line_map[3]["overflow_hints"][0]["kind"] == KIND_MUL_OVERFLOW
    # Program-wide summary.
    assert summary["risk_totals"] == {KIND_MUL_OVERFLOW: 1}
    assert [r["py_line"] for r in summary["risks"]] == [3]


def test_analyze_unflagged_lines_get_empty_list():
    # Every mapped line gets an overflow_hints list, empty when nothing fires.
    line_map = _line_map(1, 2)
    analyze_overflow(line_map, "x = 1\ny = x + 2\n")
    assert line_map[1]["overflow_hints"] == []
    assert line_map[2]["overflow_hints"] == []


def test_analyze_risk_totals_ordered_and_zero_omitted():
    # A runtime product (line 3) and an in-loop accumulator (line 5): both kinds
    # present, ordered mul-overflow before mul-accumulate.
    src = "a = 2\nb = 3\nc = a * b\nfor i in range(10):\n    c *= i\n"
    summary = analyze_overflow(_line_map(1, 2, 3, 4, 5), src)
    assert list(summary["risk_totals"].items()) == [
        (KIND_MUL_OVERFLOW, 1),
        (KIND_MUL_ACCUMULATE, 1),
    ]
    assert [(r["py_line"], r["kind"]) for r in summary["risks"]] == [
        (3, KIND_MUL_OVERFLOW),
        (5, KIND_MUL_ACCUMULATE),
    ]


def test_analyze_does_not_disturb_existing_fields():
    # Regression: the pass only adds overflow_hints, leaving prior annotations
    # (here a strength_hints placeholder) untouched.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000",
                    "strength_hints": [{"kind": "mul-pow2", "message": "x"}]}}
    analyze_overflow(line_map, "a = w * h\n")
    assert line_map[1]["strength_hints"] == [{"kind": "mul-pow2", "message": "x"}]
    assert line_map[1]["overflow_hints"][0]["kind"] == KIND_MUL_OVERFLOW


def test_analyze_empty_line_map_still_reports_source_summary():
    summary = analyze_overflow({}, "a = w * h\n")
    # No mapped lines to annotate, but the source-level summary still reports it.
    assert summary["risk_totals"] == {KIND_MUL_OVERFLOW: 1}
    assert summary["risks"][0]["py_line"] == 1


# ─── End-to-end: /compile carries the overflow summary + matches real asm ────

def _asm_for_line(body: dict, py_line: str) -> str:
    """Join the display-asm text lines that a Python line maps to."""
    mapping = body["line_map"][py_line]
    return "\n".join(body["asm_lines"][i - 1] for i in mapping["asm_lines"])


@needs_gcc
async def test_compile_response_includes_overflow_summary(client):
    r = await client.post("/compile", json={"code": "w = 5\nh = 6\na = w * h\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["overflow_summary"] is not None
    totals = body["overflow_summary"]["risk_totals"]
    assert totals.get(KIND_MUL_OVERFLOW) == 1
    # The flagged line carries the hint inline too.
    assert body["line_map"]["3"]["overflow_hints"][0]["kind"] == KIND_MUL_OVERFLOW
    # Every mapped line exposes an overflow_hints list (empty where none fires).
    for mapping in body["line_map"].values():
        assert "overflow_hints" in mapping
        assert isinstance(mapping["overflow_hints"], list)


@needs_gcc
async def test_compile_runtime_product_really_emits_imul(client):
    # Ground the hint in reality: an unknown × unknown product must actually
    # compile to an `imul` — exactly the instruction the hint points at.
    r = await client.post("/compile", json={"code": "w = 5\nh = 6\na = w * h\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["3"]["overflow_hints"][0]["kind"] == KIND_MUL_OVERFLOW
    asm = _asm_for_line(body, "3")
    assert "imul" in asm


@needs_gcc
async def test_compile_loop_accumulator_emits_imul(client):
    # A `*=` accumulator inside a loop is flagged mul-accumulate and really
    # compiles to an `imul` in the loop body.
    code = "fact = 1\nfor i in range(1, 13):\n    fact *= i\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["3"]["overflow_hints"][0]["kind"] == KIND_MUL_ACCUMULATE
    asm = _asm_for_line(body, "3")
    assert "imul" in asm


@needs_gcc
async def test_compile_pow2_multiply_is_not_flagged_as_overflow(client):
    # `a * 8` is a strength-reduced shift (the strength pass's lane); the overflow
    # pass must stay quiet on a literal-operand multiply so the signals don't
    # overlap on the same line.
    r = await client.post("/compile", json={"code": "a = 5\nb = a * 8\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["2"]["overflow_hints"] == []
    assert body["overflow_summary"]["risk_totals"] == {}


@needs_gcc
async def test_compile_no_multiplication_has_empty_overflow_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\nprint(x)\n"})
    assert r.status_code == 200
    summary = r.json()["overflow_summary"]
    assert summary["risk_totals"] == {}
    assert summary["risks"] == []
