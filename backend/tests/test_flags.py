"""
Tests for the EFLAGS producer/consumer map feature (feat/eflags-map).

Two layers:
  * Pure-function unit tests for `classify_flag_effect` / `analyze_flag_effects`
    — no gcc required.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the flag signal reaches the API response — in particular that a
    Python comparison produces a `set-cmp` producer feeding a `use` consumer.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.flags import analyze_flag_effects, classify_flag_effect

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


# ─── Unit: classify_flag_effect ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # set-cmp — the dedicated flag setters (size suffixes fold by prefix)
        ("cmp", "set-cmp"), ("cmpl", "set-cmp"), ("cmpb", "set-cmp"),
        ("test", "set-cmp"), ("testl", "set-cmp"),
        # set-alu — arithmetic / logic / shift that sets flags as a side effect
        ("add", "set-alu"), ("addl", "set-alu"), ("subl", "set-alu"),
        ("andl", "set-alu"), ("orl", "set-alu"), ("xorl", "set-alu"),
        ("incl", "set-alu"), ("decl", "set-alu"), ("negl", "set-alu"),
        ("imull", "set-alu"), ("idivl", "set-alu"), ("mull", "set-alu"),
        ("sall", "set-alu"), ("sarl", "set-alu"), ("shll", "set-alu"),
        ("shrl", "set-alu"), ("roll", "set-alu"), ("rorl", "set-alu"),
        # use — flag consumers: conditional jumps, setcc, cmov, carry-chain
        ("jl", "use"), ("jge", "use"), ("je", "use"), ("jne", "use"),
        ("jle", "use"), ("jg", "use"), ("jb", "use"), ("ja", "use"),
        ("js", "use"), ("jns", "use"), ("jo", "use"), ("jp", "use"),
        ("sete", "use"), ("setl", "use"), ("setne", "use"),
        ("cmovl", "use"), ("cmovge", "use"),
        ("adc", "use"), ("adcl", "use"), ("sbb", "use"), ("sbbl", "use"),
        # flag-neutral — must be None, never forced into a bucket
        ("mov", None), ("movl", None), ("movzbl", None), ("movsbl", None),
        ("lea", None), ("leal", None),          # lea does NOT set flags
        ("not", None), ("notl", None),          # not does NOT set flags
        ("jmp", None), ("jmpl", None),          # unconditional: reads nothing
        ("jecxz", None), ("jcxz", None),        # test %ecx, not the flags
        ("push", None), ("pushl", None), ("pop", None), ("popl", None),
        ("call", None), ("ret", None), ("leave", None), ("nop", None),
        ("cltd", None), ("cdq", None),          # sign-extend, no flags
        # x87 / SSE FP under the fixed build — left uncounted (conservative)
        ("fadd", None), ("fmul", None), ("fldl", None),
        ("addsd", None), ("mulss", None), ("cmpsd", None), ("subsd", None),
        # empty / junk
        ("", None),
    ],
)
def test_classify_flag_effect(mnemonic, expected):
    assert classify_flag_effect(mnemonic) == expected


def test_classify_flag_effect_is_case_insensitive():
    assert classify_flag_effect("CMPL") == "set-cmp"
    assert classify_flag_effect("Jge") == "use"
    assert classify_flag_effect("ADDL") == "set-alu"


def test_classify_flag_effect_adc_sub_are_not_confused():
    # `adc`/`sbb` (use) must not be swallowed by the `add`/`sub` set-alu prefixes,
    # and vice versa — the roles are opposites (consume carry vs. set flags).
    assert classify_flag_effect("adcl") == "use"
    assert classify_flag_effect("sbbl") == "use"
    assert classify_flag_effect("addl") == "set-alu"
    assert classify_flag_effect("subl") == "set-alu"


def test_classify_flag_effect_cmov_not_read_as_cmp():
    # `cmov*` begins with "cm" like `cmp` but is a consumer, not a set-cmp.
    assert classify_flag_effect("cmovl") == "use"
    assert classify_flag_effect("cmpl") == "set-cmp"


# ─── Unit: analyze_flag_effects (pure, no gcc) ───────────────────────────────

def test_analyze_flag_effects_counts_per_line_and_total():
    asm_lines = [
        "movl -4(%ebp), %eax",   # 1 → neutral
        "cmpl -8(%ebp), %eax",   # 2 → set-cmp
        "jge .L2",               # 3 → use
        "addl $1, -4(%ebp)",     # 4 → set-alu
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#FF6B6B"},
        2: {"c_lines": [2], "asm_lines": [4], "color": "#4ECDC4"},
    }

    summary = analyze_flag_effects(line_map, asm_lines)

    # Per-line annotations written in place, zero roles omitted, display order.
    assert line_map[1]["flag_effect_counts"] == {"set-cmp": 1, "use": 1}
    assert line_map[2]["flag_effect_counts"] == {"set-alu": 1}

    # Program-wide totals in display order (set-cmp < set-alu < use).
    assert summary["flag_totals"] == {"set-cmp": 1, "set-alu": 1, "use": 1}


def test_analyze_flag_effects_totals_are_ordered():
    # Even if roles are first seen out of order, the summary keys come out in the
    # fixed display order (set-cmp < set-alu < use).
    asm_lines = [
        "jne .L3",            # use
        "addl %eax, %edx",    # set-alu
        "testl %eax, %eax",   # set-cmp
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_flag_effects(line_map, asm_lines)
    assert list(summary["flag_totals"].keys()) == ["set-cmp", "set-alu", "use"]


def test_analyze_flag_effects_ignores_out_of_range_asm_lines():
    asm_lines = ["cmpl $0, -4(%ebp)"]  # set-cmp at index 1
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_flag_effects(line_map, asm_lines)
    # The stray index 99 is skipped, not crashed on.
    assert line_map[1]["flag_effect_counts"] == {"set-cmp": 1}
    assert summary["flag_totals"] == {"set-cmp": 1}


def test_analyze_flag_effects_empty_line_map():
    assert analyze_flag_effects({}, []) == {"flag_totals": {}}


def test_analyze_flag_effects_flag_neutral_line_is_empty():
    # A line whose asm is all neutral moves/calls has an empty flag map; the
    # program total is likewise empty.
    asm_lines = ["movl $1, -4(%ebp)", "call helper", "leave", "ret"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4], "color": "#000"}}
    summary = analyze_flag_effects(line_map, asm_lines)
    assert line_map[1]["flag_effect_counts"] == {}
    assert summary["flag_totals"] == {}


def test_analyze_flag_effects_line_with_no_instructions():
    # A line mapping to an empty asm list carries an empty flag map.
    line_map = {1: {"c_lines": [1], "asm_lines": [], "color": "#000"}}
    summary = analyze_flag_effects(line_map, [".L2:", "ret"])
    assert line_map[1]["flag_effect_counts"] == {}
    assert summary["flag_totals"] == {}


def test_analyze_flag_effects_counts_sum_to_totals():
    # Invariant: summing every line's per-role counts reproduces the totals map.
    asm_lines = [
        "cmpl $5, -4(%ebp)",   # set-cmp
        "jle .L2",             # use
        "subl $1, -4(%ebp)",   # set-alu
        "testl %eax, %eax",    # set-cmp
        "je .L3",              # use
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3], "color": "#111"},
        3: {"c_lines": [3], "asm_lines": [4, 5], "color": "#222"},
    }
    summary = analyze_flag_effects(line_map, asm_lines)
    combined: dict = {}
    for m in line_map.values():
        for role, n in m["flag_effect_counts"].items():
            combined[role] = combined.get(role, 0) + n
    assert combined == summary["flag_totals"]
    assert summary["flag_totals"] == {"set-cmp": 2, "set-alu": 1, "use": 2}


# ─── End-to-end: /compile carries the flag signal ────────────────────────────

@needs_gcc
async def test_compile_response_includes_flag_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert "flag_summary" in body and body["flag_summary"] is not None
    totals = body["flag_summary"]["flag_totals"]
    assert isinstance(totals, dict)
    # Every mapped line carries a flag_effect_counts map.
    for mapping in body["line_map"].values():
        assert "flag_effect_counts" in mapping


@needs_gcc
async def test_compile_comparison_produces_setcmp_and_use(client):
    # The headline lesson: a Python comparison lowers to a `cmp` (set-cmp) that
    # feeds a conditional jump (use). A straight-line program with no comparison
    # must not exhibit the `use` role; one with an `if`/`while` must.
    plain = await client.post("/compile", json={"code": "x = 5\ny = x + 7\n"})
    assert plain.status_code == 200
    assert plain.json()["flag_summary"]["flag_totals"].get("use", 0) == 0

    code = "n = 10\nt = 0\nwhile t < n:\n    t = t + 1\nprint(t)\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["flag_summary"]["flag_totals"]
    assert totals.get("set-cmp", 0) > 0, f"expected a cmp/test, got {totals}"
    assert totals.get("use", 0) > 0, f"expected a conditional jump, got {totals}"


@needs_gcc
async def test_compile_flag_totals_equal_sum_of_lines(client):
    # Invariant end-to-end: the program totals are exactly the sum of the per-line
    # flag counts.
    code = "a = 3\nb = 4\nif a < b:\n    c = a + b\nelse:\n    c = a - b\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    combined: dict = {}
    for m in body["line_map"].values():
        for role, n in m.get("flag_effect_counts", {}).items():
            combined[role] = combined.get(role, 0) + n
    assert combined == body["flag_summary"]["flag_totals"]
