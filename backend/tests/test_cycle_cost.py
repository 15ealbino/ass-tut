"""
Tests for the cycle-cost estimate feature (feat/cycle-cost-estimate).

Two layers:
  * Pure-function unit tests for `cycle_weight` / `analyze_cycles` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the cycle signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.cycle_cost import (
    DEFAULT_WEIGHT,
    _WEIGHT_PREFIXES,
    analyze_cycles,
    cycle_weight,
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


# ─── Unit: cycle_weight ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # integer divide — the dominant cost, all size variants
        ("idivl", 20), ("idiv", 20), ("divl", 20), ("divsd", 20),
        # x87 divide / sqrt
        ("fdivl", 18), ("fsqrt", 18),
        # integer multiply
        ("imull", 3), ("imul", 3), ("mull", 3), ("mulsd", 3),
        # call / return
        ("call", 4), ("calll", 4), ("ret", 3),
        # x87 float ALU
        ("fmul", 5), ("faddl", 5), ("fsubl", 5),
        ("fldz", 2), ("fld", 2), ("fistpl", 2),
        # branches — jmp before the catch-all j; conditional jumps
        ("jmp", 2), ("je", 2), ("jne", 2), ("jl", 2), ("loop", 3),
        # cheap one-cycle staples must all fall through to the default
        ("movl", DEFAULT_WEIGHT), ("addl", DEFAULT_WEIGHT), ("subl", DEFAULT_WEIGHT),
        ("pushl", DEFAULT_WEIGHT), ("popl", DEFAULT_WEIGHT), ("leal", DEFAULT_WEIGHT),
        ("cmpl", DEFAULT_WEIGHT), ("testl", DEFAULT_WEIGHT), ("sete", DEFAULT_WEIGHT),
        ("cltd", DEFAULT_WEIGHT), ("nop", DEFAULT_WEIGHT), ("xorl", DEFAULT_WEIGHT),
        ("sall", DEFAULT_WEIGHT), ("", DEFAULT_WEIGHT),
    ],
)
def test_cycle_weight(mnemonic, expected):
    assert cycle_weight(mnemonic) == expected


def test_default_weight_is_one():
    # The whole model hangs on cheap staples costing 1; guard the constant.
    assert DEFAULT_WEIGHT == 1


def test_weight_prefixes_no_shadowing():
    """Ordering invariant for the prefix table: under first-match-wins lookup, an
    entry is unreachable if any EARLIER entry's prefix is a prefix of it — every
    mnemonic that would match the later entry already matched the earlier one. A
    future addition that violated this (e.g. adding "id" before "idiv") would
    silently change weights, so assert the invariant directly rather than trust
    manual ordering.
    """
    prefixes = [p for p, _ in _WEIGHT_PREFIXES]
    for i, earlier in enumerate(prefixes):
        for later in prefixes[i + 1:]:
            assert not later.startswith(earlier), (
                f"'{later}' is shadowed by earlier prefix '{earlier}' — reorder so "
                f"the more specific prefix comes first"
            )


# ─── Unit: analyze_cycles (pure, no gcc) ─────────────────────────────────────

def test_analyze_cycles_sums_per_line_and_total():
    asm_lines = [
        "movl $1, -4(%ebp)",   # asm 1 → weight 1
        "imull %edx, %eax",    # asm 2 → weight 3
        "call helper",         # asm 3 → weight 4
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
    }

    summary = analyze_cycles(line_map, asm_lines)

    # Per-line annotations written in place.
    assert line_map[1]["cycle_estimate"] == 1       # one move
    assert line_map[2]["cycle_estimate"] == 7       # imul(3) + call(4)

    # Program-wide total and hotspot ranking (costliest first).
    assert summary["total_cycles"] == 8
    assert summary["hotspots"] == [
        {"py_line": 2, "cycles": 7},
        {"py_line": 1, "cycles": 1},
    ]


def test_cycle_ranking_differs_from_instruction_count():
    """The headline lesson: the costliest line is not always the longest.

    Line 1 is five cheap moves (5 instructions, 5 cycles). Line 2 is a single
    signed divide setup (2 instructions, 1 + 20 = 21 cycles). By instruction
    COUNT line 1 wins; by cycle COST line 2 wins. analyze_cycles must rank by
    cost, inverting the count order.
    """
    asm_lines = [
        "movl %eax, -4(%ebp)",  # 1
        "movl %ebx, -8(%ebp)",  # 2
        "movl %ecx, -12(%ebp)", # 3
        "movl %edx, -16(%ebp)", # 4
        "movl %esi, -20(%ebp)", # 5
        "cltd",                 # 6 → 1
        "idivl %ecx",           # 7 → 20
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4, 5], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [6, 7], "color": "#111"},
    }

    summary = analyze_cycles(line_map, asm_lines)

    assert line_map[1]["cycle_estimate"] == 5
    assert line_map[2]["cycle_estimate"] == 21
    # Line 2 is costlier despite mapping to FEWER instructions than line 1.
    assert len(line_map[2]["asm_lines"]) < len(line_map[1]["asm_lines"])
    assert [h["py_line"] for h in summary["hotspots"]] == [2, 1]


def test_analyze_cycles_hotspot_tiebreak_by_line():
    # Equal cost → deterministic order by ascending py_line.
    asm_lines = ["addl $1, %eax", "subl $1, %eax"]
    line_map = {
        5: {"c_lines": [5], "asm_lines": [2], "color": "#000"},
        3: {"c_lines": [3], "asm_lines": [1], "color": "#111"},
    }
    summary = analyze_cycles(line_map, asm_lines)
    assert [h["py_line"] for h in summary["hotspots"]] == [3, 5]


def test_analyze_cycles_ignores_out_of_range_asm_lines():
    asm_lines = ["idivl %ecx"]  # weight 20 at index 1
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_cycles(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["cycle_estimate"] == 20
    assert summary["total_cycles"] == 20


def test_analyze_cycles_empty_line_map():
    assert analyze_cycles({}, []) == {"total_cycles": 0, "hotspots": []}


def test_analyze_cycles_line_with_no_instructions():
    # A line mapping to nothing (e.g. a bare directive region) has zero cost and
    # is excluded from the hotspot list.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000"}}
    summary = analyze_cycles(line_map, ["movl $1, %eax"])
    assert line_map[1]["cycle_estimate"] == 0
    assert summary["hotspots"] == []
    assert summary["total_cycles"] == 0


# ─── End-to-end: /compile carries the cycle signal ───────────────────────────

@needs_gcc
async def test_compile_response_includes_cycle_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "cycle_summary" in body and body["cycle_summary"] is not None
    cs = body["cycle_summary"]
    assert cs["total_cycles"] > 0
    assert isinstance(cs["hotspots"], list)
    # Every mapped line carries a cycle_estimate.
    for mapping in body["line_map"].values():
        assert "cycle_estimate" in mapping


@needs_gcc
async def test_compile_total_cycles_equals_sum_of_lines(client):
    # Invariant: the program total is exactly the sum of the per-line estimates.
    r = await client.post("/compile", json={"code": "for i in range(4):\n    x = i * i\n"})
    assert r.status_code == 200
    body = r.json()
    per_line = sum(m["cycle_estimate"] for m in body["line_map"].values())
    assert body["cycle_summary"]["total_cycles"] == per_line


@needs_gcc
async def test_compile_division_costs_more_than_its_instruction_count(client):
    # a // b compiles to cltd + idivl (+ moves): the divide's weight (20) makes
    # that line's cycle_estimate far exceed its raw instruction count, which is
    # the whole point of the weighting.
    code = "def f(a, b):\n    return a // b\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    # Some mapped line's cycle estimate must exceed its asm_count by a wide
    # margin (a pure-move line has estimate == count; a divide line does not).
    gaps = [
        m["cycle_estimate"] - m.get("asm_count", 0)
        for m in body["line_map"].values()
    ]
    assert max(gaps) >= 15


@needs_gcc
async def test_compile_cheap_program_has_no_amplified_line(client):
    # A program with no multiply/divide/call/branch is all one-cycle staples, so
    # every line's cycle_estimate equals its instruction count (no amplification).
    r = await client.post("/compile", json={"code": "x = 5\ny = 7\n"})
    assert r.status_code == 200
    body = r.json()
    for m in body["line_map"].values():
        assert m["cycle_estimate"] == m.get("asm_count", 0)
