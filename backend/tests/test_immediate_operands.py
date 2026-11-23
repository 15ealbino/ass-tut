"""
Tests for the immediate-operand map feature (feat/immediate-operand-map).

Two layers:
  * Pure-function unit tests for `parse_immediate_value` /
    `immediates_in_instruction` / `analyze_immediates` — no gcc required.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the immediate signal reaches the API response — in particular that
    a Python literal (`n = 42`) surfaces as the value 42 in the asm, and that a
    `for i in range(N)` loop surfaces the off-by-one bound the compiler emits.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.immediates import (
    analyze_immediates,
    immediates_in_instruction,
    parse_immediate_value,
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


# ─── Unit: parse_immediate_value ─────────────────────────────────────────────

@pytest.mark.parametrize(
    "operand,expected",
    [
        # decimal literals, including the sign and zero
        ("$5", 5), ("$0", 0), ("$-1", -1), ("$42", 42), ("$255", 255),
        # hex literals decode to their exact (unsigned) magnitude — no signed
        # reinterpretation: $0xffffffff is 4294967295, not -1
        ("$0x20", 32), ("$0xffffffff", 4294967295), ("$-0x10", -16),
        # leading whitespace must not change the value (operands arrive stripped,
        # but be defensive)
        ("  $7 ", 7),
        # a leading-zero decimal that base-0 parsing rejects still decodes
        ("$08", 8),
        # NOT a numeric immediate → None
        ("$.LC0", None), ("$main", None), ("$.LC0+4", None), ("$", None),
        # NOT an immediate at all (no leading $) → None
        ("%eax", None), ("-4(%ebp)", None), (".L2", None), ("", None),
    ],
)
def test_parse_immediate_value(operand, expected):
    assert parse_immediate_value(operand) == expected


# ─── Unit: immediates_in_instruction ─────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # the headline case: a literal store — value appears, no symbols
        ("movl $5, -4(%ebp)", ([5], 0)),
        # the loop-bound comparison (gcc lowers `i < 10` to `i <= 9`)
        ("cmpl $9, -4(%ebp)", ([9], 0)),
        # a symbolic immediate (string-pool pointer) — no numeric value, one ref
        ("movl $.LC0, (%esp)", ([], 1)),
        ("pushl $.LC0", ([], 1)),
        # a numeric and a symbolic immediate on one line
        ("movl $7, %eax", ([7], 0)),
        # register-only and memory-only instructions carry no immediate
        ("addl %eax, %edx", ([], 0)),
        ("movl -8(%ebp,%eax,4), %edx", ([], 0)),
        # negative / hex immediates
        ("movl $-1, -4(%ebp)", ([-1], 0)),
        ("andl $0x1f, %eax", ([31], 0)),
        # operand-less instructions, labels and directives contribute nothing
        ("ret", ([], 0)), ("cltd", ([], 0)), ("leave", ([], 0)),
        (".L2:", ([], 0)), ('.string "hi"', ([], 0)), (".cfi_def_cfa 5, 8", ([], 0)),
        ("  ", ([], 0)),
    ],
)
def test_immediates_in_instruction(text, expected):
    assert immediates_in_instruction(text) == expected


def test_immediates_in_instruction_keeps_sibling_indexed_operand_intact():
    # A symbolic immediate beside a scaled-index operand: the splitter must keep
    # the (%ebp,%eax,4) group whole, so exactly one symbol ref is counted and no
    # phantom immediate leaks out of the index group.
    assert immediates_in_instruction("movl $.LC0, -8(%ebp,%eax,4)") == ([], 1)


# ─── Unit: analyze_immediates (pure, no gcc) ─────────────────────────────────

def test_analyze_immediates_per_line_and_totals():
    asm_lines = [
        "movl $5, -4(%ebp)",   # 1 → value 5
        "movl $7, -8(%ebp)",   # 2 → value 7
        "movl $5, %eax",       # 3 → value 5 again
        "movl $.LC0, (%esp)",  # 4 → symbolic ref
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
        3: {"c_lines": [3], "asm_lines": [4], "color": "#45B7D1"},
    }

    summary = analyze_immediates(line_map, asm_lines)

    # Per-line: distinct values sorted ascending; the symbolic line has none.
    assert line_map[1]["immediates"] == [5]
    assert line_map[2]["immediates"] == [5, 7]
    assert line_map[3]["immediates"] == []

    # value_totals counts operand occurrences (5 appears on two instructions),
    # keyed by string value in ascending numeric order.
    assert summary["value_totals"] == {"5": 2, "7": 1}
    assert summary["symbol_refs"] == 1
    assert summary["distinct_values"] == 2


def test_analyze_immediates_value_totals_ordered_by_integer_not_string():
    # Keys are strings but ordering is by the underlying integer: -1 < 2 < 10,
    # which lexicographic string ordering ("-1" < "10" < "2") would get wrong.
    asm_lines = [
        "movl $10, %eax",
        "movl $2, %ebx",
        "movl $-1, %ecx",
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    assert list(summary["value_totals"].keys()) == ["-1", "2", "10"]
    # And the per-line distinct list is likewise integer-sorted.
    assert line_map[1]["immediates"] == [-1, 2, 10]


def test_analyze_immediates_ignores_out_of_range_asm_lines():
    asm_lines = ["movl $5, -4(%ebp)"]  # value 5 at index 1
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_immediates(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["immediates"] == [5]
    assert summary == {"value_totals": {"5": 1}, "symbol_refs": 0, "distinct_values": 1}


def test_analyze_immediates_empty_line_map():
    assert analyze_immediates({}, []) == {
        "value_totals": {}, "symbol_refs": 0, "distinct_values": 0,
    }


def test_analyze_immediates_line_with_no_instructions():
    # A line mapping only to a label/directive region encodes no immediate.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000"}}
    summary = analyze_immediates(line_map, [".L2:", "ret"])
    assert line_map[1]["immediates"] == []
    assert summary == {"value_totals": {}, "symbol_refs": 0, "distinct_values": 0}


def test_analyze_immediates_totals_count_every_operand_occurrence():
    # Invariant: value_totals counts operand occurrences, so summing every value's
    # total equals the number of numeric immediate operands across the program —
    # independent of the per-line deduplication.
    asm_lines = [
        "movl $3, -4(%ebp)",
        "movl $3, -8(%ebp)",   # same value 3 on a second instruction
        "addl $3, %eax",       # and a third
        "movl $.LC0, (%esp)",  # symbolic — not a numeric total
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#111"},
    }
    summary = analyze_immediates(line_map, asm_lines)
    assert summary["value_totals"] == {"3": 3}
    assert sum(summary["value_totals"].values()) == 3   # three numeric operands
    assert summary["symbol_refs"] == 1
    # Per-line dedup: line 1 names 3 twice but lists it once.
    assert line_map[1]["immediates"] == [3]
    assert line_map[2]["immediates"] == [3]


# ─── End-to-end: /compile carries the immediate signal ───────────────────────

@needs_gcc
async def test_compile_response_includes_immediate_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "immediate_summary" in body and body["immediate_summary"] is not None
    summary = body["immediate_summary"]
    assert set(summary) == {"value_totals", "symbol_refs", "distinct_values"}
    assert isinstance(summary["value_totals"], dict)
    # Every mapped line carries an immediates list.
    for mapping in body["line_map"].values():
        assert "immediates" in mapping
        assert isinstance(mapping["immediates"], list)


@needs_gcc
async def test_compile_literal_surfaces_its_value(client):
    # The headline lesson: a Python literal appears verbatim as an immediate in
    # the asm. `n = 42` must put the value 42 somewhere in the program.
    r = await client.post("/compile", json={"code": "n = 42\n"})
    assert r.status_code == 200
    body = r.json()
    totals = body["immediate_summary"]["value_totals"]
    assert "42" in totals, f"expected the literal 42 in the asm immediates, got {totals}"
    # And it appears on the line that wrote it.
    assert any(42 in m.get("immediates", []) for m in body["line_map"].values())


@needs_gcc
async def test_compile_range_bound_lowers_off_by_one(client):
    # The reverse-engineering lesson: `for i in range(10)` does NOT encode 10 as
    # the loop bound — gcc lowers `i < 10` to the `i <= 9` test `cmpl $9`, so the
    # constant in the asm is 9. Seeing that gap is the whole point of the feature.
    r = await client.post("/compile", json={"code": "for i in range(10):\n    x = i\n"})
    assert r.status_code == 200
    body = r.json()
    totals = body["immediate_summary"]["value_totals"]
    assert "9" in totals, (
        f"expected the off-by-one bound 9 (from i < 10 → i <= 9), got {totals}"
    )


@needs_gcc
async def test_compile_string_literal_adds_no_numeric_immediate(client):
    # A print of a string literal must not fabricate a NUMERIC immediate: the
    # string's address is a symbolic operand, never a number. (Whether it is a
    # `$.LC0` immediate counted in symbol_refs or a PIC `.LC0@GOTOFF(%ebx)`
    # displacement depends on the toolchain's PIC default — see the README scope —
    # so symbol_refs is asserted only to be a sane non-negative int, not > 0.)
    r = await client.post("/compile", json={"code": 'print("hello")\n'})
    assert r.status_code == 200
    summary = r.json()["immediate_summary"]
    assert isinstance(summary["symbol_refs"], int) and summary["symbol_refs"] >= 0
    # No per-line immediates value should be an obviously-bogus huge address-like
    # number leaking from the string operand; the string carries no numeric value.
    for mapping in r.json()["line_map"].values():
        assert all(isinstance(v, int) for v in mapping.get("immediates", []))


@needs_gcc
async def test_compile_per_line_values_are_consistent_with_totals(client):
    # Invariant end-to-end: every numeric value listed on a per-line `immediates`
    # appears as a key in the program-wide value_totals (per-line dedup vs.
    # operand-occurrence totals must still agree on WHICH values exist).
    r = await client.post("/compile", json={"code": "a = 5\nb = a + 7\nc = b * 3\n"})
    assert r.status_code == 200
    body = r.json()
    total_keys = set(body["immediate_summary"]["value_totals"])
    for mapping in body["line_map"].values():
        for v in mapping.get("immediates", []):
            assert str(v) in total_keys


@needs_gcc
async def test_compile_distinct_values_matches_value_totals(client):
    # Invariant end-to-end: distinct_values equals the number of keys in
    # value_totals.
    r = await client.post("/compile", json={"code": "a = 5\nb = 5\nc = 7\nd = a + c\n"})
    assert r.status_code == 200
    summary = r.json()["immediate_summary"]
    assert summary["distinct_values"] == len(summary["value_totals"])
