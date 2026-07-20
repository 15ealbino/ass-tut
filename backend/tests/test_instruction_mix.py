"""
Tests for the assembly instruction-mix feature (feat/asm-instruction-mix).

The mix is orthogonal to the existing div/mul/call cost flags: where the flags
single out the few *expensive* mnemonics, the mix sorts *every* mapped
instruction into one of six categories (mem / compute / branch / call / stack /
other) so a learner can read the shape of each Python line's assembly.

Two layers, mirroring test_cost_analysis.py:
  * Pure-function unit tests for `classify_category` / `analyze_cost` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the mix signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import analyze_cost, classify_category

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


# ─── Unit: classify_category ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # data movement / memory traffic (incl. size-suffixed + widening)
        ("movl", "mem"),
        ("movzbl", "mem"),
        ("movsbl", "mem"),
        ("leal", "mem"),
        ("cltd", "mem"),
        ("cmovl", "mem"),
        ("fldl", "mem"),
        ("fstpl", "mem"),
        # arithmetic / logic
        ("addl", "compute"),
        ("subl", "compute"),
        ("imull", "compute"),
        ("mull", "compute"),
        ("idivl", "compute"),
        ("divl", "compute"),
        ("negl", "compute"),
        ("andl", "compute"),
        ("orl", "compute"),
        ("xorl", "compute"),
        ("sall", "compute"),
        ("sarl", "compute"),
        ("shrl", "compute"),
        ("notl", "compute"),
        ("fmul", "compute"),
        # control flow: jumps + the compares/setcc that feed them
        ("jmp", "branch"),
        ("je", "branch"),
        ("jne", "branch"),
        ("jle", "branch"),
        ("jge", "branch"),
        ("cmpl", "branch"),
        ("testl", "branch"),
        ("sete", "branch"),
        ("setne", "branch"),
        # call / return overhead
        ("call", "call"),
        ("calll", "call"),
        ("ret", "call"),
        ("leave", "call"),
        # explicit stack management
        ("pushl", "stack"),
        ("popl", "stack"),
        # unknown / empty → total function never returns None
        ("nop", "other"),
        ("cpuid", "other"),
        ("", "other"),
    ],
)
def test_classify_category(mnemonic, expected):
    assert classify_category(mnemonic) == expected


def test_classify_category_is_total():
    # Unlike the flag classifier, every mnemonic must land in exactly one bucket.
    for m in ["movl", "addl", "jmp", "call", "pushl", "wibble", ""]:
        assert classify_category(m) in {
            "mem", "compute", "branch", "call", "stack", "other"
        }


# ─── Unit: analyze_cost mix annotations (pure, no gcc) ───────────────────────

def test_analyze_cost_adds_category_counts_and_totals():
    # Line 1: a plain move (mem). Line 2: a multiply (compute) + a call (call).
    asm_lines = [
        "movl $1, -4(%ebp)",   # asm line 1 → mem
        "imull %edx, %eax",    # asm line 2 → compute
        "call helper",         # asm line 3 → call
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
    }

    summary = analyze_cost(line_map, asm_lines)

    assert line_map[1]["category_counts"] == {"mem": 1}
    assert line_map[2]["category_counts"] == {"compute": 1, "call": 1}
    assert summary["category_totals"] == {"mem": 1, "compute": 1, "call": 1}


def test_category_counts_sum_equals_asm_count():
    asm_lines = [
        "movl $0, %eax",       # mem
        "addl %edx, %eax",     # compute
        "cmpl $10, %eax",      # branch
        "jle .L2",             # branch
        "pushl %ebp",          # stack
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4, 5], "color": "#000"}}
    analyze_cost(line_map, asm_lines)
    counts = line_map[1]["category_counts"]
    # Every mapped (in-range) instruction is classified exactly once.
    assert sum(counts.values()) == line_map[1]["asm_count"]
    assert counts == {"mem": 1, "compute": 1, "branch": 2, "stack": 1}


def test_category_counts_omits_zero_categories_and_is_ordered():
    # Only categories with a nonzero count appear, and in canonical display order
    # (mem, compute, branch, call, stack, other) — not asm-encounter order.
    asm_lines = ["call f", "movl %eax, %ebx", "addl $1, %ebx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    analyze_cost(line_map, asm_lines)
    assert list(line_map[1]["category_counts"].keys()) == ["mem", "compute", "call"]


def test_analyze_cost_mix_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped for the mix, so the
    # category sum can legitimately trail asm_count (which counts the raw mapping).
    asm_lines = ["movl $1, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    analyze_cost(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["category_counts"] == {"mem": 1}
    assert sum(line_map[1]["category_counts"].values()) == 1


def test_analyze_cost_empty_line_map_has_empty_mix():
    summary = analyze_cost({}, [])
    assert summary["category_totals"] == {}
    assert summary["total_instructions"] == 0


def test_mix_does_not_disturb_existing_cost_fields():
    # Regression: the existing asm_count / flags / hotspots contract is intact.
    asm_lines = ["imull %edx, %eax", "call helper"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_cost(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == ["mul", "call"]
    assert summary["total_instructions"] == 2
    assert summary["hotspots"][0]["py_line"] == 1


# ─── End-to-end: /compile carries the mix signal ─────────────────────────────

@needs_gcc
async def test_compile_response_includes_category_mix(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    cs = body["cost_summary"]
    assert "category_totals" in cs
    totals = cs["category_totals"]
    assert isinstance(totals, dict) and totals
    # Every category key is one of the six known buckets.
    assert set(totals).issubset({"mem", "compute", "branch", "call", "stack", "other"})
    # Program-wide mix accounts for every counted instruction.
    assert sum(totals.values()) == cs["total_instructions"]
    # Every mapped line carries a category_counts map.
    for mapping in body["line_map"].values():
        assert "category_counts" in mapping
        assert sum(mapping["category_counts"].values()) == mapping["asm_count"]


@needs_gcc
async def test_compile_mix_flags_compute_on_multiply(client):
    # a * b compiles to an imul → the 'compute' bucket must be populated.
    r = await client.post("/compile", json={"code": "def f(a, b):\n    return a * b\n"})
    assert r.status_code == 200
    totals = r.json()["cost_summary"]["category_totals"]
    assert totals.get("compute", 0) > 0


@needs_gcc
async def test_compile_mix_flags_call_on_function_call(client):
    # Calling a helper emits a `call` instruction → the 'call' bucket appears.
    code = "def helper(a):\n    return a + 1\nx = helper(3)\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["cost_summary"]["category_totals"]
    assert totals.get("call", 0) > 0


@needs_gcc
async def test_compile_mix_has_branch_on_conditional(client):
    # An if/loop produces cmp + conditional jumps → the 'branch' bucket appears.
    code = "x = 0\nfor i in range(5):\n    if i > 2:\n        x = x + i\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["cost_summary"]["category_totals"]
    assert totals.get("branch", 0) > 0
