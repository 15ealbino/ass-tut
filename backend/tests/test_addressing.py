"""
Tests for the addressing-mode map feature (feat/addressing-modes).

Two layers:
  * Pure-function unit tests for `classify_operand` / `operand_modes` /
    `analyze_addressing` — no gcc required.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the addressing signal reaches the API response — in particular
    that array indexing produces the scaled-index ("indexed") mode.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.addressing import (
    analyze_addressing,
    classify_operand,
    operand_modes,
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


# ─── Unit: classify_operand ──────────────────────────────────────────────────

@pytest.mark.parametrize(
    "operand,expected",
    [
        # immediate — literal values and address constants
        ("$5", "immediate"), ("$-1", "immediate"), ("$0", "immediate"),
        ("$.LC0", "immediate"),
        # register-direct — including 8/16-bit spellings and the x87 stack reg
        # (whose parens hold no %, so it is NOT a memory operand)
        ("%eax", "register"), ("%ebp", "register"), ("%al", "register"),
        ("%st(0)", "register"),
        # displacement — base register + (optional) displacement, no index
        ("-4(%ebp)", "displacement"), ("(%eax)", "displacement"),
        ("8(%ebp)", "displacement"), ("sym@GOTOFF(%ebx)", "displacement"),
        # indexed — a comma in the base/index group means a scaled index
        # register: the array-element fingerprint
        ("-24(%ebp,%eax,4)", "indexed"), ("(%eax,%ecx,4)", "indexed"),
        (".L4(,%eax,4)", "indexed"),
        # direct — bare symbols / code targets, and the catch-all
        (".L2", "direct"), ("helper", "direct"), ("main", "direct"),
        ("*%eax", "direct"), ("", "direct"),
    ],
)
def test_classify_operand(operand, expected):
    assert classify_operand(operand) == expected


def test_classify_operand_strips_whitespace():
    # Operands arrive already split, but stray whitespace must not change the mode.
    assert classify_operand("  -4(%ebp) ") == "displacement"
    assert classify_operand("  $7 ") == "immediate"


# ─── Unit: operand_modes ─────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # AT&T reads left→right (source, …, dest); modes are returned in that order.
        ("movl $1, -4(%ebp)", ["immediate", "displacement"]),
        ("movl -24(%ebp,%eax,4), %eax", ["indexed", "register"]),
        ("addl %eax, %edx", ["register", "register"]),
        ("call helper", ["direct"]),
        ("jmp .L2", ["direct"]),
        # operand-less instructions contribute nothing
        ("ret", []), ("cltd", []), ("leave", []),
        # labels and directives are not instructions
        (".L2:", []), (".cfi_def_cfa 5, 8", []), ("  ", []),
    ],
)
def test_operand_modes(text, expected):
    assert operand_modes(text) == expected


def test_operand_modes_keeps_indexed_operand_intact():
    # The scaled-index operand carries internal commas; the splitter must keep it
    # as ONE operand, not shatter it into "(%ebp", "%eax", "4)".
    assert operand_modes("movl %eax, -8(%ebp,%ecx,4)") == ["register", "indexed"]


# ─── Unit: analyze_addressing (pure, no gcc) ─────────────────────────────────

def test_analyze_addressing_counts_per_line_and_total():
    asm_lines = [
        "movl $1, -4(%ebp)",             # 1 → immediate, displacement
        "movl -8(%ebp,%eax,4), %edx",    # 2 → indexed, register
        "call helper",                   # 3 → direct
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [2, 3], "color": "#4ECDC4"},
    }

    summary = analyze_addressing(line_map, asm_lines)

    # Per-line annotations written in place, zero modes omitted, display order.
    assert line_map[1]["addressing_counts"] == {"immediate": 1, "displacement": 1}
    assert line_map[2]["addressing_counts"] == {"register": 1, "indexed": 1, "direct": 1}

    # Program-wide totals in display order.
    assert summary["addressing_totals"] == {
        "immediate": 1, "register": 1, "displacement": 1, "indexed": 1, "direct": 1,
    }


def test_analyze_addressing_totals_are_ordered():
    # Even if higher-order modes are seen first, the summary keys come out in the
    # fixed display order (immediate < register < displacement < indexed < direct).
    asm_lines = [
        "jmp .L2",                     # direct
        "movl -4(%ebp,%eax,4), %eax",  # indexed, register
        "movl $1, %ebx",               # immediate, register
        "movl -8(%ebp), %ecx",         # displacement, register
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"}}
    summary = analyze_addressing(line_map, asm_lines)
    assert list(summary["addressing_totals"].keys()) == [
        "immediate", "register", "displacement", "indexed", "direct",
    ]


def test_analyze_addressing_ignores_out_of_range_asm_lines():
    asm_lines = ["movl $1, -4(%ebp)"]  # immediate + displacement at index 1
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_addressing(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["addressing_counts"] == {"immediate": 1, "displacement": 1}
    assert summary["addressing_totals"] == {"immediate": 1, "displacement": 1}


def test_analyze_addressing_empty_line_map():
    assert analyze_addressing({}, []) == {"addressing_totals": {}}


def test_analyze_addressing_line_with_no_instructions():
    # A line mapping only to a label/directive region has no operands and an
    # empty addressing map; the program total is likewise empty.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000"}}
    summary = analyze_addressing(line_map, [".L2:", "ret"])
    assert line_map[1]["addressing_counts"] == {}
    assert summary["addressing_totals"] == {}


def test_analyze_addressing_operand_counts_sum_to_totals():
    # Invariant: summing every line's per-mode counts reproduces the totals map.
    asm_lines = [
        "movl $1, -4(%ebp)",
        "movl -4(%ebp), %eax",
        "addl %eax, %edx",
        "movl %edx, -8(%ebp,%eax,4)",
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#111"},
    }
    summary = analyze_addressing(line_map, asm_lines)
    combined: dict = {}
    for m in line_map.values():
        for mode, n in m["addressing_counts"].items():
            combined[mode] = combined.get(mode, 0) + n
    assert combined == summary["addressing_totals"]


# ─── End-to-end: /compile carries the addressing signal ──────────────────────

@needs_gcc
async def test_compile_response_includes_addressing_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "addressing_summary" in body and body["addressing_summary"] is not None
    totals = body["addressing_summary"]["addressing_totals"]
    assert isinstance(totals, dict)
    # Every mapped line carries an addressing_counts map.
    for mapping in body["line_map"].values():
        assert "addressing_counts" in mapping


@needs_gcc
async def test_compile_plain_program_is_displacement_heavy(client):
    # At -O0 every local is spilled to the stack, so a plain arithmetic program's
    # operands are dominated by the base+displacement (%ebp) mode.
    r = await client.post("/compile", json={"code": "x = 5\ny = x + 7\nz = y + x\n"})
    assert r.status_code == 200
    totals = r.json()["addressing_summary"]["addressing_totals"]
    assert totals.get("displacement", 0) > 0


@needs_gcc
async def test_compile_array_index_produces_indexed_mode(client):
    # The headline lesson: array-element access `xs[i]` compiles to a scaled
    # base+index operand (%ebp,%eax,4) — the "indexed" addressing mode. A program
    # with no array indexing must not exhibit it; one with indexing must.
    plain = await client.post("/compile", json={"code": "a = 1\nb = a + 2\n"})
    assert plain.status_code == 200
    assert plain.json()["addressing_summary"]["addressing_totals"].get("indexed", 0) == 0

    code = "xs = [10, 20, 30]\ns = 0\nfor i in range(3):\n    s = s + xs[i]\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    totals = body["addressing_summary"]["addressing_totals"]
    assert totals.get("indexed", 0) > 0, (
        f"expected a scaled-index operand from xs[i], got totals={totals}"
    )
    # And at least one Python line's own map carries the indexed mode.
    assert any(
        m.get("addressing_counts", {}).get("indexed", 0) > 0
        for m in body["line_map"].values()
    )


@needs_gcc
async def test_compile_addressing_totals_equal_sum_of_lines(client):
    # Invariant end-to-end: the program totals are exactly the sum of the per-line
    # addressing counts.
    r = await client.post("/compile", json={"code": "xs = [1, 2, 3]\nfor i in range(3):\n    y = xs[i] * 2\n"})
    assert r.status_code == 200
    body = r.json()
    combined: dict = {}
    for m in body["line_map"].values():
        for mode, n in m.get("addressing_counts", {}).items():
            combined[mode] = combined.get(mode, 0) + n
    assert combined == body["addressing_summary"]["addressing_totals"]
