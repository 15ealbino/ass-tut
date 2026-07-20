"""
Tests for the assembly cost-analysis feature (feat/asm-cost-analysis).

Two layers:
  * Pure-function unit tests for `_classify_mnemonic` / `analyze_cost` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the cost signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import _classify_mnemonic, analyze_cost

# asyncio_mode=auto (pytest.ini) auto-detects the async e2e tests; the sync unit
# tests below need no marker.


# ─── gcc availability guard (mirrors the real pipeline's requirements) ───────

def _gcc_m32_available() -> bool:
    if shutil.which("gcc") is None:
        return False
    try:
        # Include <stdio.h> like the real pipeline so this guard also detects a
        # missing 32-bit multilib (headers such as bits/libc-header-start.h),
        # not just a missing gcc binary.
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


# ─── Unit: _classify_mnemonic ────────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        ("idivl", "div"),
        ("idiv", "div"),
        ("divl", "div"),
        ("divsd", "div"),
        ("imull", "mul"),
        ("imul", "mul"),
        ("mull", "mul"),
        ("mulsd", "mul"),
        ("call", "call"),
        ("calll", "call"),
        # Unremarkable staples must NOT be flagged.
        ("movl", None),
        ("addl", None),
        ("subl", None),
        ("pushl", None),
        ("ret", None),
        ("leal", None),
        ("cmpl", None),
        ("", None),
    ],
)
def test_classify_mnemonic(mnemonic, expected):
    assert _classify_mnemonic(mnemonic) == expected


# ─── Unit: analyze_cost (pure, no gcc) ───────────────────────────────────────

def test_analyze_cost_counts_and_flags():
    # Two Python lines: line 1 → a plain move; line 2 → a multiply + a call.
    asm_lines = [
        "movl $1, -4(%ebp)",   # asm line 1
        "imull %edx, %eax",    # asm line 2
        "call helper",         # asm line 3
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
    }

    summary = analyze_cost(line_map, asm_lines)

    # Per-line annotations were written in place.
    assert line_map[1]["asm_count"] == 1
    assert line_map[1]["flags"] == []
    assert line_map[2]["asm_count"] == 2
    assert line_map[2]["flags"] == ["mul", "call"]  # ordered div<mul<call

    # Summary aggregates.
    assert summary["total_instructions"] == 3
    # Hotspots sorted by count desc; line 2 (2 instr) before line 1 (1 instr).
    assert [h["py_line"] for h in summary["hotspots"]] == [2, 1]
    assert summary["hotspots"][0]["flags"] == ["mul", "call"]


def test_analyze_cost_division_flag():
    asm_lines = ["cltd", "idivl %ecx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#FF6B6B"}}
    summary = analyze_cost(line_map, asm_lines)
    assert line_map[1]["flags"] == ["div"]
    assert summary["total_instructions"] == 2


def test_analyze_cost_flag_order_is_stable():
    # A line hitting all three classes must list them div → mul → call.
    asm_lines = ["call f", "imull %eax, %eax", "idivl %ecx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    analyze_cost(line_map, asm_lines)
    assert line_map[1]["flags"] == ["div", "mul", "call"]


def test_analyze_cost_ignores_out_of_range_asm_lines():
    # Defensive: an asm index past the end of the list must not crash.
    asm_lines = ["movl $1, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_cost(line_map, asm_lines)
    # count reflects the mapping length; the stray index is simply skipped.
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == []
    assert summary["total_instructions"] == 2


def test_analyze_cost_empty_line_map():
    summary = analyze_cost({}, [])
    # category_totals was added by the instruction-mix feature; empty here.
    assert summary == {"total_instructions": 0, "hotspots": [], "category_totals": {}}


# ─── End-to-end: /compile carries the cost signal ────────────────────────────

@needs_gcc
async def test_compile_response_includes_cost_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "cost_summary" in body and body["cost_summary"] is not None
    cs = body["cost_summary"]
    assert cs["total_instructions"] > 0
    assert isinstance(cs["hotspots"], list)
    # Every mapped line carries asm_count / flags.
    for mapping in body["line_map"].values():
        assert "asm_count" in mapping
        assert "flags" in mapping


@needs_gcc
async def test_compile_flags_multiplication(client):
    # a * b must compile to an imul → "mul" flag on that Python line.
    code = "def f(a, b):\n    return a * b\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    all_flags = {f for m in body["line_map"].values() for f in m["flags"]}
    assert "mul" in all_flags


@needs_gcc
async def test_compile_flags_division(client):
    # a // b must compile to an idiv → "div" flag on that Python line.
    code = "def f(a, b):\n    return a // b\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    all_flags = {f for m in body["line_map"].values() for f in m["flags"]}
    assert "div" in all_flags


@needs_gcc
async def test_compile_simple_move_not_flagged(client):
    # A bare constant assignment should be cheap: no expensive-op flags.
    r = await client.post("/compile", json={"code": "x = 5\n"})
    assert r.status_code == 200
    body = r.json()
    all_flags = {f for m in body["line_map"].values() for f in m["flags"]}
    assert all_flags == set()


@needs_gcc
async def test_compile_hotspots_sorted_descending(client):
    code = "for i in range(10):\n    x = i * i\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    hotspots = r.json()["cost_summary"]["hotspots"]
    counts = [h["asm_count"] for h in hotspots]
    assert counts == sorted(counts, reverse=True)
