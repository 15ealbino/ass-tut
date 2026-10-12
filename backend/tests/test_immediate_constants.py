"""
Tests for the immediate-constant map feature (feat/immediate-constants).

Two layers:
  * Pure-function unit tests for `parse_immediate` / `immediates_in_instruction` /
    `analyze_immediates` — no gcc required, so they always run.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the immediate-constant signal reaches the API response — in
    particular that a source literal appears as its `$`-immediate and that a
    power-of-two multiply surfaces the compiler-synthesised shift count.

The e2e tests are skipped automatically if gcc (with -m32 support, including the
32-bit libc headers the real pipeline needs) is missing, so the suite still
passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.immediates import (
    analyze_immediates,
    immediates_in_instruction,
    parse_immediate,
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


# ─── Unit: parse_immediate ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    "operand,expected",
    [
        # decimal literals, including sign and zero
        ("$42", 42), ("$0", 0), ("$-1", -1), ("$-16", -16),
        # hex literals, case-insensitive, with sign
        ("$0x1f", 31), ("$0X1F", 31), ("$-0x10", -16), ("$0xff", 255),
        # whitespace is stripped defensively
        ("  $7  ", 7),
    ],
)
def test_parse_immediate_numeric(operand, expected):
    assert parse_immediate(operand) == expected


@pytest.mark.parametrize(
    "operand",
    [
        "$.LC0",        # symbolic / address immediate — not a value
        "$main",        # function-address immediate
        "$sym+4",       # symbol-relative immediate
        "%eax",         # register-direct
        "-4(%ebp)",     # memory operand
        "(%eax)",       # memory operand, no displacement
        ".L2",          # bare symbol / code target
        "",             # empty
        "$",            # lone dollar, no digits
        "$0x",          # malformed hex (no digits)
        "$1f",          # hex without 0x prefix is not a decimal literal
    ],
)
def test_parse_immediate_non_numeric_returns_none(operand):
    assert parse_immediate(operand) is None


# ─── Unit: immediates_in_instruction ─────────────────────────────────────────

def test_immediates_in_instruction_basic():
    # The immediate operand is recovered; the memory destination contributes none.
    assert immediates_in_instruction("movl $42, -4(%ebp)") == [42]


def test_immediates_in_instruction_strength_reduction_constants():
    # The shift count ($3) and the modulo mask ($7) are compiler-synthesised
    # constants — exactly the "not in your Python" case the feature teaches.
    assert immediates_in_instruction("sall $3, %eax") == [3]
    assert immediates_in_instruction("andl $7, %eax") == [7]


def test_immediates_in_instruction_sorted_and_distinct():
    # Two distinct immediates in one (contrived) instruction come back sorted;
    # a repeat of the same value is reported once.
    assert immediates_in_instruction("foo $10, $3, $10") == [3, 10]


def test_immediates_in_instruction_indexed_operand_has_no_immediate():
    # A scaled-index memory operand carries a scale (4) inside the parens, but
    # that is not a `$`-immediate and must not be mistaken for one.
    assert immediates_in_instruction("movl -8(%ebp,%eax,4), %eax") == []


def test_immediates_in_instruction_negative_and_hex():
    assert immediates_in_instruction("cmpl $-1, %eax") == [-1]
    assert immediates_in_instruction("andl $0xff, %eax") == [255]


@pytest.mark.parametrize(
    "line",
    [
        ".L2:",                     # label
        "  .cfi_def_cfa 4",         # directive
        ".long 5",                  # directive with a bare number (not a $-imm)
        "ret",                      # operand-less instruction
        "leave",                    # operand-less instruction
        "",                         # blank
        "   ",                      # whitespace only
    ],
)
def test_immediates_in_instruction_non_instructions(line):
    assert immediates_in_instruction(line) == []


def test_immediates_in_instruction_symbolic_immediate_excluded():
    # An address immediate ($.LC0) is deliberately not recovered.
    assert immediates_in_instruction("movl $.LC0, (%esp)") == []


# ─── Unit: analyze_immediates ────────────────────────────────────────────────

def test_analyze_immediates_annotates_and_totals():
    asm_lines = [
        "movl $42, -4(%ebp)",   # 42
        "sall $3, -4(%ebp)",    # 3
        "cmpl $42, -4(%ebp)",   # 42 again (different instruction)
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)
    # Per-line distinct values, sorted ascending.
    assert line_map[1]["immediate_values"] == [3, 42]
    assert line_map[2]["immediate_values"] == [42]
    # Totals count instructions that embed each value: 42 appears in two
    # instructions, 3 in one. Ordered by value ascending.
    assert summary["value_totals"] == {3: 1, 42: 2}
    assert list(summary["value_totals"].keys()) == [3, 42]
    assert summary["distinct"] == 2


def test_analyze_immediates_value_twice_in_one_instruction_counts_once():
    # Mirrors the register/addressing convention: a value named twice in a single
    # instruction counts once toward its total.
    asm_lines = ["foo $5, $5"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediate_values"] == [5]
    assert summary["value_totals"] == {5: 1}
    assert summary["distinct"] == 1


def test_analyze_immediates_ignores_out_of_range_asm_lines():
    asm_lines = ["movl $9, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["immediate_values"] == [9]
    assert summary["value_totals"] == {9: 1}


def test_analyze_immediates_empty_line_map():
    assert analyze_immediates({}, []) == {"value_totals": {}, "distinct": 0}


def test_analyze_immediates_line_with_no_immediates():
    # A line mapping only to register-only / memory-only instructions has an empty
    # immediate list; the program total is likewise empty.
    asm_lines = ["movl -4(%ebp), %eax", "addl %eax, %edx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediate_values"] == []
    assert summary == {"value_totals": {}, "distinct": 0}


def test_analyze_immediates_totals_equal_sum_over_instructions():
    # Invariant: each value's total equals the number of mapped instructions that
    # embed it (distinct-per-instruction).
    asm_lines = [
        "movl $1, -4(%ebp)",   # 1
        "movl $1, -8(%ebp)",   # 1
        "andl $7, %eax",       # 7
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)
    assert summary["value_totals"] == {1: 2, 7: 1}
    assert summary["distinct"] == 2


# ─── End-to-end: /compile carries the immediate-constant signal ──────────────

@needs_gcc
async def test_compile_response_includes_immediate_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "immediate_summary" in body and body["immediate_summary"] is not None
    summary = body["immediate_summary"]
    assert isinstance(summary["value_totals"], dict)
    assert isinstance(summary["distinct"], int)
    # Every mapped line carries an immediate_values list.
    for mapping in body["line_map"].values():
        assert "immediate_values" in mapping
        assert isinstance(mapping["immediate_values"], list)


@needs_gcc
async def test_compile_source_literal_appears_as_immediate(client):
    # Pillar 1: a Python literal lands in the asm as its `$`-immediate. The value
    # 42 from `x = 42` must appear somewhere in the program's immediates.
    r = await client.post("/compile", json={"code": "x = 42\n"})
    assert r.status_code == 200
    body = r.json()
    # JSON object keys are strings; recover the integer values.
    values = {int(k) for k in body["immediate_summary"]["value_totals"]}
    assert 42 in values, f"expected 42 among program immediates, got {sorted(values)}"
    # And the line that owns the assignment embeds it.
    assert any(
        42 in m.get("immediate_values", []) for m in body["line_map"].values()
    )


@needs_gcc
async def test_compile_power_of_two_multiply_surfaces_shift_count(client):
    # Pillar 2: even at -O0 gcc strength-reduces `* 8` to a left shift by 3, so
    # the compiler-synthesised constant 3 — which is NOT in the Python source —
    # appears in the immediates, while 8 does not reach the asm as an imul operand.
    r = await client.post("/compile", json={"code": "x = 5\ny = x * 8\n"})
    assert r.status_code == 200
    body = r.json()
    values = {int(k) for k in body["immediate_summary"]["value_totals"]}
    assert 3 in values, f"expected synthesised shift count 3, got {sorted(values)}"


@needs_gcc
async def test_compile_immediate_totals_consistent_with_lines(client):
    # Invariant end-to-end: every value listed on a line also appears in the
    # program-wide value_totals, and `distinct` matches the number of keys.
    r = await client.post("/compile", json={"code": "a = 10\nb = a + 20\nc = b * 4\n"})
    assert r.status_code == 200
    body = r.json()
    summary = body["immediate_summary"]
    total_keys = {int(k) for k in summary["value_totals"]}
    assert summary["distinct"] == len(summary["value_totals"])
    seen_on_lines = set()
    for m in body["line_map"].values():
        seen_on_lines.update(m.get("immediate_values", []))
    # Every value that appears on a line is accounted for in the totals.
    assert seen_on_lines <= total_keys


@needs_gcc
async def test_compile_transpile_error_still_422(client):
    # The feature must not perturb the error path: an unsupported construct still
    # returns HTTP 422, with no immediate_summary payload.
    r = await client.post("/compile", json={"code": "import os\n"})
    assert r.status_code == 422
