"""
Tests for the stack-frame-map feature (feat/stack-frame-map).

The frame map is the memory-side complement to the register footprint: where the
footprint answers *which registers* a Python line touches, the frame map answers
*which stack slots* — the %ebp-relative displacements that ARE the stack frame at
gcc -O0 (locals at negative offsets, incoming args at positive offsets).

Two layers, mirroring test_register_footprint.py / test_cost_analysis.py:
  * Pure-function unit tests for `canonical_slot` / `_stack_offsets_in_instruction`
    / `analyze_stack` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the frame signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import (
    _stack_offsets_in_instruction,
    analyze_cost,
    analyze_stack,
    canonical_slot,
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


# ─── Unit: canonical_slot ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "disp,expected",
    [
        (-4, "-4(%ebp)"),
        (-8, "-8(%ebp)"),
        (0, "(%ebp)"),      # zero displacement is written bare, matching gcc
        (8, "8(%ebp)"),
        (12, "12(%ebp)"),
    ],
)
def test_canonical_slot(disp, expected):
    assert canonical_slot(disp) == expected


# ─── Unit: _stack_offsets_in_instruction ─────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # simple local write / read
        ("movl $1, -4(%ebp)", {-4}),
        ("movl -8(%ebp), %eax", {-8}),
        # two slots in one instruction
        ("movl -8(%ebp), -4(%ebp)", {-8, -4}),
        # positive-offset incoming argument
        ("movl 8(%ebp), %edx", {8}),
        # bare base == displacement 0
        ("movl %eax, (%ebp)", {0}),
        # indexed (array element access) contributes only the base displacement
        ("movl -24(%ebp,%eax,4), %eax", {-24}),
        # hex displacement is parsed defensively
        ("movl 0x10(%ebp), %eax", {16}),
        ("movl -0x8(%ebp), %eax", {-8}),
        # %esp-relative slots are NOT the frame — must be ignored
        ("movl %eax, (%esp)", set()),
        ("movl $4, 4(%esp)", set()),
        # a register-only instruction touches no slot
        ("addl %edx, %eax", set()),
        # %ebp used as a plain register (push) is not a slot reference
        ("pushl %ebp", set()),
        ("", set()),
    ],
)
def test_stack_offsets_in_instruction(text, expected):
    assert _stack_offsets_in_instruction(text) == expected


# ─── Unit: analyze_stack (pure, no gcc) ──────────────────────────────────────

def test_analyze_stack_slots_and_totals():
    # `x = a + b` shape: read arg slots 8/12(%ebp), write local -4(%ebp).
    asm_lines = [
        "movl 8(%ebp), %edx",     # asm line 1  -> slot 8
        "movl 12(%ebp), %eax",    # asm line 2  -> slot 12
        "addl %edx, %eax",        # asm line 3  -> no slot
        "movl %eax, -4(%ebp)",    # asm line 4  -> slot -4
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"},
    }
    summary = analyze_stack(line_map, asm_lines)

    # Ordered by offset ascending: local (-4) first, then args (8, 12).
    assert line_map[1]["stack_slots"] == ["-4(%ebp)", "8(%ebp)", "12(%ebp)"]
    assert summary["slot_totals"] == {"-4(%ebp)": 1, "8(%ebp)": 1, "12(%ebp)": 1}
    assert summary["frame_slots"] == 3
    # Most-negative offset is -4 → locals_bytes lower bound is 4.
    assert summary["locals_bytes"] == 4


def test_analyze_stack_counts_repeated_slot_across_instructions():
    # The same local slot is spilled and re-read — two instructions reference it.
    asm_lines = [
        "movl %eax, -4(%ebp)",
        "movl -4(%ebp), %edx",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert line_map[1]["stack_slots"] == ["-4(%ebp)"]
    assert summary["slot_totals"] == {"-4(%ebp)": 2}
    assert summary["frame_slots"] == 1


def test_analyze_stack_slot_named_twice_in_one_instruction_counts_once():
    # A slot referenced twice within a single instruction counts once in totals.
    asm_lines = ["movl -4(%ebp), -4(%ebp)"]  # contrived, but exercises de-dup
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert line_map[1]["stack_slots"] == ["-4(%ebp)"]
    assert summary["slot_totals"] == {"-4(%ebp)": 1}


def test_analyze_stack_locals_bytes_is_deepest_local():
    # locals_bytes is the magnitude of the most-negative offset seen.
    asm_lines = [
        "movl %eax, -4(%ebp)",
        "movl %eax, -24(%ebp)",
        "movl 8(%ebp), %eax",     # positive offset must not affect locals_bytes
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert summary["locals_bytes"] == 24
    assert summary["frame_slots"] == 3


def test_analyze_stack_no_locals_means_zero_locals_bytes():
    # Only positive (argument) offsets → no local region → locals_bytes 0.
    asm_lines = ["movl 8(%ebp), %eax", "movl 12(%ebp), %edx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert summary["locals_bytes"] == 0
    assert summary["slot_totals"] == {"8(%ebp)": 1, "12(%ebp)": 1}


def test_analyze_stack_ignores_esp_slots():
    # Outgoing-argument staging is %esp-relative and is NOT part of the frame map.
    asm_lines = ["movl %eax, (%esp)", "movl $4, 4(%esp)", "movl %eax, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert line_map[1]["stack_slots"] == ["-4(%ebp)"]
    assert summary["slot_totals"] == {"-4(%ebp)": 1}


def test_analyze_stack_totals_ordered_by_offset():
    # slot_totals keys must come back ordered by numeric offset ascending,
    # regardless of encounter order in the asm.
    asm_lines = [
        "movl 12(%ebp), %eax",
        "movl -8(%ebp), %eax",
        "movl 8(%ebp), %eax",
        "movl -4(%ebp), %eax",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert list(summary["slot_totals"].keys()) == [
        "-8(%ebp)", "-4(%ebp)", "8(%ebp)", "12(%ebp)",
    ]


def test_analyze_stack_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring the other
    # per-line passes.
    asm_lines = ["movl %eax, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert line_map[1]["stack_slots"] == ["-4(%ebp)"]
    assert summary["slot_totals"] == {"-4(%ebp)": 1}


def test_analyze_stack_zero_touch_line_is_empty_list():
    # A line whose only asm is a label / register-only op touches no slot.
    asm_lines = [".L2:", "addl %edx, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_stack(line_map, asm_lines)
    assert line_map[1]["stack_slots"] == []
    assert summary == {"slot_totals": {}, "frame_slots": 0, "locals_bytes": 0}


def test_analyze_stack_empty_line_map():
    summary = analyze_stack({}, [])
    assert summary == {"slot_totals": {}, "frame_slots": 0, "locals_bytes": 0}


def test_analyze_stack_does_not_disturb_cost_fields():
    # Regression: running the frame-map pass after analyze_cost leaves the
    # existing cost/mix annotations intact and merely adds `stack_slots`.
    asm_lines = ["imull %edx, %eax", "movl %eax, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_stack(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == ["mul"]
    assert line_map[1]["category_counts"] == {"mem": 1, "compute": 1}
    assert cost["total_instructions"] == 2
    # And the new field is present alongside the old ones.
    assert line_map[1]["stack_slots"] == ["-4(%ebp)"]


# ─── End-to-end: /compile carries the stack frame map ────────────────────────

@needs_gcc
async def test_compile_response_includes_stack_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["stack_summary"] is not None
    ss = body["stack_summary"]
    assert isinstance(ss["slot_totals"], dict) and ss["slot_totals"]
    assert ss["frame_slots"] == len(ss["slot_totals"])
    # At -O0 top-level locals live at negative %ebp offsets, so there is a
    # non-empty local region.
    assert ss["locals_bytes"] > 0
    # Every mapped line carries a stack_slots list.
    for mapping in body["line_map"].values():
        assert "stack_slots" in mapping
        assert isinstance(mapping["stack_slots"], list)


@needs_gcc
async def test_compile_args_appear_at_positive_offsets(client):
    # A function's parameters are incoming args at positive %ebp offsets
    # (8(%ebp), 12(%ebp) on System V i386), while its locals sit at negative
    # offsets — the central lesson of the frame map.
    code = "def f(a, b):\n    x = a + b\n    return x\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    slots = r.json()["stack_summary"]["slot_totals"]
    has_positive = any(int(s.split("(")[0]) > 0 for s in slots if s != "(%ebp)")
    has_negative = any(int(s.split("(")[0]) < 0 for s in slots if s != "(%ebp)")
    assert has_positive, f"expected an incoming-arg slot at a positive offset: {slots}"
    assert has_negative, f"expected a local slot at a negative offset: {slots}"


@needs_gcc
async def test_compile_stack_slots_ordered_by_offset(client):
    r = await client.post("/compile", json={"code": "def f(a, b):\n    return a + b\n"})
    assert r.status_code == 200
    slots = r.json()["stack_summary"]["slot_totals"]

    def _off(label: str) -> int:
        return 0 if label == "(%ebp)" else int(label.split("(")[0])

    offsets = [_off(s) for s in slots]
    assert offsets == sorted(offsets)
