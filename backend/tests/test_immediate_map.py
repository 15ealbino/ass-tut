"""
Tests for the immediate-operand map feature (feat/immediate-map).

Two layers:
  * Pure-function unit tests for `classify_immediate` / `immediate_int_value` /
    `immediates_in_instruction` / `analyze_immediates` — no gcc required.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the immediate signal reaches the API response — in particular that
    a source literal (`x = 5`) appears as a numeric immediate value, and that a
    `print("...")` program emits a symbolic ($.LC0) immediate.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.immediates import (
    analyze_immediates,
    classify_immediate,
    immediate_int_value,
    immediates_in_instruction,
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


# ─── Unit: classify_immediate ────────────────────────────────────────────────

@pytest.mark.parametrize(
    "operand,expected",
    [
        # decimal — plain numeric literals, signed and unsigned
        ("$5", "decimal"), ("$-1", "decimal"), ("$0", "decimal"), ("$+7", "decimal"),
        ("$4096", "decimal"),
        # hex — 0x-prefixed numeric literals, including signed and uppercase
        ("$0x10", "hex"), ("$-0x1", "hex"), ("$0X1F", "hex"), ("$0xdeadbeef", "hex"),
        # symbol — address constants (the ADDRESS of something, not a value)
        ("$.LC0", "symbol"), ("$main", "symbol"), ("$_GLOBAL_OFFSET_TABLE_", "symbol"),
        ("$.L2", "symbol"),
        # a lone / malformed "$" is treated as a (non-numeric) symbol, never crashed on
        ("$", "symbol"),
        # NOT immediates — a register, a memory reference, a bare label → None, so
        # the pass can never miscount a non-constant as a constant
        ("%eax", None), ("%st(0)", None), ("-4(%ebp)", None), ("(%eax)", None),
        ("-8(%ebp,%eax,4)", None), (".L2", None), ("main", None), ("*%eax", None),
        ("", None),
    ],
)
def test_classify_immediate(operand, expected):
    assert classify_immediate(operand) == expected


def test_classify_immediate_strips_whitespace():
    # Operands arrive already split, but stray whitespace must not change the kind.
    assert classify_immediate("  $7 ") == "decimal"
    assert classify_immediate("  $.LC0 ") == "symbol"
    assert classify_immediate("  %eax ") is None


# ─── Unit: immediate_int_value ───────────────────────────────────────────────

@pytest.mark.parametrize(
    "operand,expected",
    [
        ("$5", 5), ("$-1", -1), ("$0", 0), ("$+7", 7), ("$4096", 4096),
        ("$0x10", 16), ("$-0x1", -1), ("$0X1F", 31), ("$0xff", 255),
        # symbol immediates and non-immediates have no numeric value
        ("$.LC0", None), ("$main", None), ("$", None),
        ("%eax", None), ("-4(%ebp)", None), (".L2", None), ("", None),
    ],
)
def test_immediate_int_value(operand, expected):
    assert immediate_int_value(operand) == expected


# ─── Unit: immediates_in_instruction ─────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # `x = 5` → the literal 5 lands as a decimal immediate; the stack slot is
        # not an immediate and contributes nothing.
        ("movl $5, -4(%ebp)", [("decimal", 5)]),
        # `x += 1` bumps a counter with an immediate 1.
        ("addl $1, %eax", [("decimal", 1)]),
        # `if x == 0` compares against an immediate 0.
        ("cmpl $0, -4(%ebp)", [("decimal", 0)]),
        # passing a format string: the operand is the ADDRESS of a rodata entry —
        # a symbolic immediate, no numeric value.
        ("movl $.LC0, (%esp)", [("symbol", None)]),
        ("pushl $.LC0", [("symbol", None)]),
        # a hex immediate folds to its int value
        ("movl $0x10, %eax", [("hex", 16)]),
        # register/memory-only instructions carry no immediate
        ("movl -4(%ebp), %eax", []),
        ("addl %eax, %edx", []),
        # operand-less instructions, labels and directives contribute nothing
        ("ret", []), ("cltd", []), ("leave", []),
        (".L2:", []), (".long 42", []), ("  ", []),
    ],
)
def test_immediates_in_instruction(text, expected):
    assert list(immediates_in_instruction(text)) == expected


def test_immediates_in_instruction_multiple_per_line():
    # A (contrived) line with two immediate operands yields both, in order.
    assert list(immediates_in_instruction("foo $1, $0x2")) == [
        ("decimal", 1), ("hex", 2),
    ]


# ─── Unit: analyze_immediates (pure, no gcc) ─────────────────────────────────

def test_analyze_immediates_counts_values_and_totals():
    asm_lines = [
        "movl $5, -4(%ebp)",      # 1 → decimal 5
        "movl $.LC0, (%esp)",     # 2 → symbol (no value)
        "addl $1, %eax",          # 3 → decimal 1
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
    }

    summary = analyze_immediates(line_map, asm_lines)

    # Per-line: counts by kind (zeros omitted) and the distinct numeric values.
    assert line_map[1]["immediate_counts"] == {"decimal": 1}
    assert line_map[1]["immediate_values"] == [5]
    assert line_map[2]["immediate_counts"] == {"decimal": 1, "symbol": 1}
    assert line_map[2]["immediate_values"] == [1]  # symbol contributes no value

    # Program-wide totals (operand counts) + every distinct numeric value, sorted.
    assert summary["immediate_totals"] == {"decimal": 2, "symbol": 1}
    assert summary["distinct_values"] == [1, 5]


def test_analyze_immediates_totals_are_ordered():
    # Keys come out in the fixed display order decimal < hex < symbol, regardless
    # of the order the kinds are first seen.
    asm_lines = [
        "movl $.LC0, (%esp)",   # symbol first
        "movl $0x10, %eax",     # hex
        "movl $7, %ebx",        # decimal
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert list(summary["immediate_totals"].keys()) == ["decimal", "hex", "symbol"]


def test_analyze_immediates_distinct_values_dedupe_and_sort():
    # The same value baked in on several lines appears once, sorted ascending
    # (including negatives), and hex + decimal share one numeric space.
    asm_lines = [
        "movl $-4, %eax",
        "movl $10, %ebx",
        "movl $0xa, %ecx",   # 0xa == 10, already present → not duplicated
        "movl $2, %edx",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert summary["distinct_values"] == [-4, 2, 10]
    assert line_map[1]["immediate_values"] == [-4, 2, 10]


def test_analyze_immediates_ignores_out_of_range_asm_lines():
    asm_lines = ["movl $5, -4(%ebp)"]  # decimal 5 at index 1
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["immediate_counts"] == {"decimal": 1}
    assert line_map[1]["immediate_values"] == [5]
    assert summary["immediate_totals"] == {"decimal": 1}
    assert summary["distinct_values"] == [5]


def test_analyze_immediates_empty_line_map():
    assert analyze_immediates({}, []) == {
        "immediate_totals": {}, "distinct_values": [],
    }


def test_analyze_immediates_line_with_no_immediates():
    # A line whose asm has only registers / memory operands carries empty maps.
    asm_lines = ["movl -4(%ebp), %eax", "addl %eax, %edx", "ret"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert line_map[1]["immediate_counts"] == {}
    assert line_map[1]["immediate_values"] == []
    assert summary["immediate_totals"] == {}
    assert summary["distinct_values"] == []


def test_analyze_immediates_operand_counts_sum_to_totals():
    # Invariant: summing every line's per-kind counts reproduces the totals map.
    asm_lines = [
        "movl $5, -4(%ebp)",
        "movl $.LC0, (%esp)",
        "addl $1, %eax",
        "movl $0x20, %edx",
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)
    combined: dict = {}
    for m in line_map.values():
        for kind, n in m["immediate_counts"].items():
            combined[kind] = combined.get(kind, 0) + n
    assert combined == summary["immediate_totals"]


# ─── End-to-end: /compile carries the immediate signal ───────────────────────

@needs_gcc
async def test_compile_response_includes_immediate_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "immediate_summary" in body and body["immediate_summary"] is not None
    summary = body["immediate_summary"]
    assert isinstance(summary["immediate_totals"], dict)
    assert isinstance(summary["distinct_values"], list)
    # Every mapped line carries both per-line immediate fields.
    for mapping in body["line_map"].values():
        assert "immediate_counts" in mapping
        assert "immediate_values" in mapping


@needs_gcc
async def test_compile_source_literal_appears_as_immediate_value(client):
    # The headline lesson (pillar 1): the literal 42 you write in Python lands as a
    # numeric immediate in the machine code, readable straight off the disassembly.
    r = await client.post("/compile", json={"code": "x = 42\n"})
    assert r.status_code == 200
    body = r.json()
    assert 42 in body["immediate_summary"]["distinct_values"], (
        f"expected literal 42 among the immediates, got "
        f"{body['immediate_summary']['distinct_values']}"
    )
    # And the Python line that defined it carries 42 in its own values list.
    assert any(
        42 in m.get("immediate_values", [])
        for m in body["line_map"].values()
    )
    # A decimal immediate was counted program-wide.
    assert body["immediate_summary"]["immediate_totals"].get("decimal", 0) > 0


@needs_gcc
async def test_compile_print_emits_symbolic_immediate(client):
    # The pillar-2 lesson: passing a string literal to print() forms the ADDRESS of
    # a rodata entry — a symbolic ($.LC0) immediate, distinct from a numeric value.
    # A plain numeric program has no symbolic immediate; a print() program does.
    plain = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert plain.status_code == 200
    assert plain.json()["immediate_summary"]["immediate_totals"].get("symbol", 0) == 0

    r = await client.post("/compile", json={"code": 'print("hello")\n'})
    assert r.status_code == 200
    totals = r.json()["immediate_summary"]["immediate_totals"]
    assert totals.get("symbol", 0) > 0, (
        f"expected a symbolic immediate from the format-string address, got {totals}"
    )


@needs_gcc
async def test_compile_immediate_totals_equal_sum_of_lines(client):
    # Invariant end-to-end: the program totals are exactly the sum of the per-line
    # immediate counts.
    r = await client.post(
        "/compile", json={"code": "x = 5\nfor i in range(3):\n    x = x + 1\n"}
    )
    assert r.status_code == 200
    body = r.json()
    combined: dict = {}
    for m in body["line_map"].values():
        for kind, n in m.get("immediate_counts", {}).items():
            combined[kind] = combined.get(kind, 0) + n
    assert combined == body["immediate_summary"]["immediate_totals"]
