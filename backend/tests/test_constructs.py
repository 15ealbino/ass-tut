"""
Tests for the construct-map feature (feat/construct-map).

Three layers:
  * Pure-function unit tests for `classify_statement` / `collect_constructs` /
    `analyze_constructs` — no gcc, no transpiler.
  * A transpile-integration layer that runs the REAL transpiler (Python AST → C,
    which needs no gcc) and asserts the construct classification lines up with
    the actual py→C line map. This exercises the whole classification path in a
    toolchain-less environment.
  * End-to-end `/compile` tests that run the full transpiler + gcc pipeline and
    assert the construct signal reaches the API response. These skip
    automatically if gcc (with -m32) is missing.
"""
import ast
import shutil
import subprocess

import pytest

from app.constructs import (
    analyze_constructs,
    classify_statement,
    collect_constructs,
)
from app.transpiler import build_line_map, transpile

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


# ─── Unit: classify_statement ────────────────────────────────────────────────

def _first_stmt(src: str) -> ast.AST:
    """Parse `src` and return its first top-level statement node."""
    return ast.parse(src).body[0]


@pytest.mark.parametrize(
    "src,expected",
    [
        ("x = 1", "assign"),
        ("x += 1", "augassign"),
        ("for i in range(3):\n    pass", "for"),
        ("while x < 3:\n    pass", "while"),
        ("if x:\n    pass", "if"),
        ("def f():\n    return 1", "funcdef"),
        ("class C:\n    pass", "classdef"),
        ("return 1", "return"),
        ("break", "break"),
        ("continue", "continue"),
        ("import math", "import"),
        ("from math import sqrt", "import"),
        ("print(x)", "call"),      # bare expression that is a call
        ("x + 1", "expr"),         # bare expression that is not a call
    ],
)
def test_classify_statement(src, expected):
    # `return`/`break`/`continue` are only valid inside a function/loop, but
    # ast.parse accepts them at module level, which is all we need here.
    node = _first_stmt(src)
    assert classify_statement(node) == expected


def test_classify_statement_ignores_non_statements_and_unnamed():
    # A sub-expression is not a statement kind this pass names.
    binop = ast.parse("a + b").body[0].value  # the BinOp inside the Expr
    assert classify_statement(binop) is None
    # `pass` is a statement, but not one of the named kinds.
    assert classify_statement(_first_stmt("pass")) is None


# ─── Unit: collect_constructs ────────────────────────────────────────────────

def test_collect_constructs_maps_each_line_to_its_kind():
    src = (
        "x = 1\n"            # 1 assign
        "x += 2\n"           # 2 augassign
        "for i in range(3):\n"  # 3 for
        "    x = x + i\n"    # 4 assign
        "if x > 0:\n"        # 5 if
        "    print(x)\n"     # 6 call
    )
    got = collect_constructs(src)
    assert got == {1: "assign", 2: "augassign", 3: "for", 4: "assign", 5: "if", 6: "call"}


def test_collect_constructs_elif_is_its_own_if_line():
    src = (
        "if x > 0:\n"     # 1 if
        "    y = 1\n"     # 2 assign
        "elif x < 0:\n"   # 3 if (an elif is an If node on its own line)
        "    y = 2\n"     # 4 assign
    )
    got = collect_constructs(src)
    assert got[1] == "if"
    assert got[3] == "if"
    assert got[2] == "assign" and got[4] == "assign"


def test_collect_constructs_first_statement_on_a_line_wins():
    # Two statements share line 1; the first seen is kept.
    got = collect_constructs("a = 1; b = 2\n")
    assert got[1] == "assign"


def test_collect_constructs_syntax_error_is_empty():
    assert collect_constructs("def (:\n") == {}


# ─── Unit: analyze_constructs ────────────────────────────────────────────────

def test_analyze_constructs_annotates_and_totals():
    src = "x = 1\nfor i in range(3):\n    x = x + i\n"
    line_map = {
        1: {"c_lines": [1], "asm_lines": [], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [], "color": "#111"},
        3: {"c_lines": [3], "asm_lines": [], "color": "#222"},
    }
    summary = analyze_constructs(line_map, src)
    assert line_map[1]["construct_kind"] == "assign"
    assert line_map[2]["construct_kind"] == "for"
    assert line_map[3]["construct_kind"] == "assign"
    # Totals count mapped lines per kind, in display order (assign < for).
    assert summary["construct_totals"] == {"assign": 2, "for": 1}
    assert list(summary["construct_totals"].keys()) == ["assign", "for"]


def test_analyze_constructs_unmapped_kind_is_empty_string():
    # A `pass` line is mapped but not a named kind → empty construct, not counted.
    src = "x = 1\npass\n"
    line_map = {
        1: {"c_lines": [1], "asm_lines": [], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [], "color": "#111"},
    }
    summary = analyze_constructs(line_map, src)
    assert line_map[1]["construct_kind"] == "assign"
    assert line_map[2]["construct_kind"] == ""
    assert summary["construct_totals"] == {"assign": 1}


def test_analyze_constructs_only_counts_mapped_lines():
    # Line 2 (`y = 2`) exists in the source but is NOT in line_map; it must not
    # be counted, because the summary describes the shape of the MAPPED code.
    src = "x = 1\ny = 2\n"
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000"}}
    summary = analyze_constructs(line_map, src)
    assert summary["construct_totals"] == {"assign": 1}


def test_analyze_constructs_empty_line_map():
    assert analyze_constructs({}, "x = 1\n") == {"construct_totals": {}}


# ─── Transpile-integration (real AST + real py→C map, no gcc) ────────────────

def _line_map_from_transpile(code: str) -> dict:
    """Run the real transpiler and build a line_map from its py→C mapping with an
    empty c→asm map, so the construct pass can be exercised end-to-end without
    gcc (construct classification needs only the Python source and the mapped
    line numbers)."""
    _c_source, py_to_c = transpile(code)
    return build_line_map(code.splitlines(), py_to_c, {})


def test_integration_construct_map_matches_real_transpile():
    code = (
        "def f(n):\n"           # 1 funcdef
        "    total = 0\n"       # 2 assign
        "    for i in range(n):\n"  # 3 for
        "        total += i\n"  # 4 augassign
        "        if i == 2:\n"  # 5 if
        "            break\n"   # 6 break
        "    return total\n"    # 7 return
        "x = f(5)\n"            # 8 assign
        "print(x)\n"            # 9 call
    )
    line_map = _line_map_from_transpile(code)
    summary = analyze_constructs(line_map, code)

    # Every construct kind lands on the line that produced it (only assert lines
    # the transpiler actually mapped, so the test is robust to emission detail).
    def kind(n: int):
        return line_map[n]["construct_kind"] if n in line_map else None

    assert kind(1) == "funcdef"
    assert kind(2) == "assign"
    assert kind(3) == "for"
    assert kind(4) == "augassign"
    assert kind(5) == "if"
    assert kind(6) == "break"
    assert kind(7) == "return"
    assert kind(8) == "assign"
    assert kind(9) == "call"

    totals = summary["construct_totals"]
    assert totals.get("funcdef") == 1
    assert totals.get("for") == 1
    assert totals.get("if") == 1
    assert totals.get("break") == 1
    assert totals.get("return") == 1
    assert totals.get("call") == 1
    assert totals.get("assign") == 2       # `total = 0` and `x = f(5)`
    assert totals.get("augassign") == 1
    # Display order: funcdef precedes the data/control kinds.
    assert list(totals.keys())[0] == "funcdef"


def test_integration_every_mapped_line_has_a_construct_field():
    code = "a = 1\nb = a + 2\nwhile b > 0:\n    b -= 1\n"
    line_map = _line_map_from_transpile(code)
    analyze_constructs(line_map, code)
    for mapping in line_map.values():
        assert "construct_kind" in mapping
        assert isinstance(mapping["construct_kind"], str)


# ─── End-to-end: /compile carries the construct signal ───────────────────────

@needs_gcc
async def test_compile_response_includes_construct_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\nfor i in range(3):\n    x = x + i\n"})
    assert r.status_code == 200
    body = r.json()
    assert "construct_summary" in body and body["construct_summary"] is not None
    totals = body["construct_summary"]["construct_totals"]
    assert isinstance(totals, dict)
    assert totals.get("for") == 1
    # Every mapped line carries a construct string.
    for mapping in body["line_map"].values():
        assert "construct_kind" in mapping
        assert isinstance(mapping["construct_kind"], str)


@needs_gcc
async def test_compile_construct_marks_loop_and_assignment(client):
    r = await client.post("/compile", json={"code": "s = 0\nfor i in range(3):\n    s += i\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["line_map"]["1"]["construct_kind"] == "assign"
    assert body["line_map"]["2"]["construct_kind"] == "for"
    assert body["line_map"]["3"]["construct_kind"] == "augassign"
