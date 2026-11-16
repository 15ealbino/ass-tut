"""
Tests for the immediate-value-map feature (feat/immediate-value-map).

The immediate map is the value-level complement to the addressing-mode map: where
the addressing map COUNTS how many of a Python line's operands are immediates, the
immediate map NAMES their values — the numeric constants ($5, $100, $-1) each
line's assembly embeds. A literal traces from Python source to its `$N` immediate
(pillar 1), and the bound a guard compares against is readable straight off the
asm (pillar 2).

Two layers, mirroring test_stack_frame_map.py / test_addressing.py:
  * Pure-function unit tests for `canonical_immediate` /
    `immediate_values_in_instruction` / `analyze_immediates` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the immediate signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import analyze_cost
from app.immediates import (
    analyze_immediates,
    canonical_immediate,
    immediate_values_in_instruction,
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


# ─── Unit: canonical_immediate ───────────────────────────────────────────────

@pytest.mark.parametrize(
    "value,expected",
    [
        (5, "$5"),
        (0, "$0"),
        (-1, "$-1"),
        (100, "$100"),
        (16, "$16"),         # a hex immediate folds to its decimal label
    ],
)
def test_canonical_immediate(value, expected):
    assert canonical_immediate(value) == expected


# ─── Unit: immediate_values_in_instruction ───────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # a literal stored into a stack local
        ("movl $5, -4(%ebp)", {5}),
        # the bound of a comparison — the pillar-2 case
        ("cmpl $100, -4(%ebp)", {100}),
        # hex immediate is parsed base-16 and normalised to its int value
        ("orl $0x10, %eax", {16}),
        ("andl $0xff, %eax", {255}),
        # negative immediate (decimal and hex)
        ("movl $-1, %eax", {-1}),
        ("addl $-0x8, %esp", {-8}),
        # two immediates on one line both count
        ("movl $7, %eax\tsomething $9", {7, 9}),
        # zero — the compiler's own constant (return 0 / zero-init)
        ("movl $0, %eax", {0}),
        # a displacement is NOT an immediate: the 8 in 8(%ebp) carries no '$'
        ("movl 8(%ebp), %eax", set()),
        # symbolic address-of operands are pointers, not numeric constants
        ("pushl $.LC0", set()),
        ("movl $main, %eax", set()),
        ("movl $_shim_json_buf, %eax", set()),
        ("leal .L2(%eax), %edx", set()),
        # register-only / label / directive / empty — no immediate
        ("addl %edx, %eax", set()),
        (".L2:", set()),
        (".long 42", set()),       # a directive operand carries no '$'
        ("", set()),
    ],
)
def test_immediate_values_in_instruction(text, expected):
    assert immediate_values_in_instruction(text) == expected


def test_immediate_hex_and_decimal_fold_to_same_value():
    # $0x10 and $16 are the same constant and must produce the same int.
    assert immediate_values_in_instruction("movl $0x10, %eax") == {16}
    assert immediate_values_in_instruction("movl $16, %eax") == {16}


# ─── Unit: analyze_immediates (pure, no gcc) ─────────────────────────────────

def test_analyze_immediates_values_and_totals():
    # `x = 5; if x < 100` shape: store $5, compare against $100.
    asm_lines = [
        "movl $5, -4(%ebp)",      # asm line 1 -> $5
        "cmpl $100, -4(%ebp)",    # asm line 2 -> $100
        "addl %edx, %eax",        # asm line 3 -> no immediate
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)

    assert line_map[1]["immediates"] == ["$5"]
    assert line_map[2]["immediates"] == ["$100"]
    # Ordered by numeric value ascending.
    assert summary["immediate_totals"] == {"$5": 1, "$100": 1}
    assert summary["distinct"] == 2


def test_analyze_immediates_orders_by_numeric_value_negatives_first():
    # Encounter order is jumbled; the totals must come back ordered by numeric
    # value ascending (so -1 leads, and $100 does NOT sort before $9 as strings).
    asm_lines = [
        "movl $100, %eax",
        "movl $-1, %eax",
        "movl $9, %eax",
        "movl $0, %eax",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == ["$-1", "$0", "$9", "$100"]
    assert list(summary["immediate_totals"].keys()) == ["$-1", "$0", "$9", "$100"]


def test_analyze_immediates_distinct_per_line_but_counts_instructions():
    # The same value used on two instructions counts twice in totals, but appears
    # once in a line's distinct `immediates` list.
    asm_lines = [
        "movl $1, -4(%ebp)",
        "addl $1, -4(%ebp)",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == ["$1"]
    assert summary["immediate_totals"] == {"$1": 2}
    assert summary["distinct"] == 1


def test_analyze_immediates_value_named_twice_in_one_instruction_counts_once():
    # A value referenced twice within a single instruction counts once in totals.
    asm_lines = ["movl $7, $7"]  # contrived, but exercises per-instruction de-dup
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == ["$7"]
    assert summary["immediate_totals"] == {"$7": 1}


def test_analyze_immediates_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring the other
    # per-line passes.
    asm_lines = ["movl $5, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == ["$5"]
    assert summary["immediate_totals"] == {"$5": 1}


def test_analyze_immediates_zero_immediate_line_is_empty_list():
    # A line whose only asm is a label / register-only op embeds no immediate.
    asm_lines = [".L2:", "addl %edx, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == []
    assert summary == {"immediate_totals": {}, "distinct": 0}


def test_analyze_immediates_excludes_symbolic_operands_end_to_end():
    # A line that only references a symbol address ($.LC0) yields no immediate,
    # while a sibling line with a real constant does — the symbolic/numeric split
    # the feature hinges on.
    asm_lines = [
        "pushl $.LC0",            # address of a string literal — excluded
        "movl $42, %eax",         # a real constant — included
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediates"] == []
    assert line_map[2]["immediates"] == ["$42"]
    assert summary["immediate_totals"] == {"$42": 1}
    assert summary["distinct"] == 1


def test_analyze_immediates_empty_line_map():
    summary = analyze_immediates({}, [])
    assert summary == {"immediate_totals": {}, "distinct": 0}


def test_analyze_immediates_does_not_disturb_cost_fields():
    # Regression: running the immediate pass after analyze_cost leaves the existing
    # cost/mix annotations intact and merely adds `immediates`.
    asm_lines = ["imull $3, %edx, %eax", "movl %eax, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_immediates(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == ["mul"]
    assert cost["total_instructions"] == 2
    # And the new field is present alongside the old ones.
    assert line_map[1]["immediates"] == ["$3"]


# ─── End-to-end: /compile carries the immediate-value map ────────────────────

# NOTE on what the e2e tests assert. gcc lowers a COMPARISON bound by
# normalising it: `x < 100` becomes `cmpl $99, …` (x < 100 ⟺ x <= 99 for ints),
# and a `range(3)` loop test becomes `cmpl $2, …`. So a comparison bound is NOT a
# stable immediate to assert on. A DIRECT ASSIGNMENT literal, by contrast, is
# emitted verbatim — `x = 42` is always `movl $42, …` at -O0 — so the e2e tests
# hang their value assertions on assignment literals and otherwise check only
# structural invariants that hold regardless of how the compiler lowers arithmetic.

@needs_gcc
async def test_compile_response_includes_immediate_summary(client):
    # Two direct assignment literals; both constants are emitted verbatim and must
    # surface in the program-wide map (an assignment literal is not normalised the
    # way a comparison bound is — see the NOTE above).
    code = "x = 5\ny = 42\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    assert body["immediate_summary"] is not None
    summ = body["immediate_summary"]
    totals = summ["immediate_totals"]
    assert isinstance(totals, dict) and totals
    assert summ["distinct"] == len(totals)
    # The literals you typed appear as immediates — the pillar-1 "trace your
    # constant from source to asm" case.
    assert "$5" in totals, totals
    assert "$42" in totals, totals
    # Every label is numeric: no symbolic address-of operand ($.LC0, $main) leaked.
    for label in totals:
        assert label.startswith("$")
        int(label[1:])  # raises if a symbolic operand leaked in
    # Every mapped line carries an immediates list.
    for mapping in body["line_map"].values():
        assert "immediates" in mapping
        assert isinstance(mapping["immediates"], list)


@needs_gcc
async def test_compile_immediate_totals_ordered_by_value(client):
    # Assignment literals (verbatim immediates) chosen so their string order would
    # differ from numeric order ($100 sorts before $9 as a string) — the totals
    # must come back in NUMERIC order.
    r = await client.post("/compile", json={"code": "x = 5\ny = 100\nz = 9\n"})
    assert r.status_code == 200
    totals = r.json()["immediate_summary"]["immediate_totals"]
    values = [int(k[1:]) for k in totals]  # strip the leading '$'
    assert values == sorted(values), totals


@needs_gcc
async def test_compile_line_immediates_trace_the_literal(client):
    # The $5 immediate must appear on the Python line that wrote the literal 5 —
    # the direct "trace your constant from source to asm" lesson. A plain
    # assignment literal is emitted verbatim, so this is robust to normalisation.
    r = await client.post("/compile", json={"code": "a = 5\nb = a + 2\n"})
    assert r.status_code == 200
    body = r.json()
    line1 = body["line_map"]["1"]
    assert "$5" in line1["immediates"], line1["immediates"]


@needs_gcc
async def test_compile_symbolic_addresses_not_counted_as_immediates(client):
    # print() references the format-string's address (a $.LC0 / GOT operand). That
    # symbolic operand must NOT appear as a numeric immediate — only real numeric
    # constants may. This asserts the exclusion property (every key is numeric)
    # without pinning a specific compiler-normalised comparison bound.
    code = "x = 7\nfor i in range(3):\n    print(i)\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["immediate_summary"]["immediate_totals"]
    assert totals, "expected at least one numeric immediate"
    for label in totals:
        assert label.startswith("$")
        int(label[1:])  # raises if a symbolic operand ($.LC0, $main) leaked in
    # The assignment literal 7 is emitted verbatim and must be present.
    assert "$7" in totals, totals
