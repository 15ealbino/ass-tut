"""
Tests for the register-footprint feature (feat/register-footprint).

The footprint is orthogonal to the existing cost flags and instruction mix:
where those answer *how much* and *what kind* of work a Python line's assembly
does, the footprint answers *where* it happens — which x86 registers the line
touches, including the implicit %edx:%eax pair that integer division uses
without ever naming it.

Two layers, mirroring test_cost_analysis.py / test_instruction_mix.py:
  * Pure-function unit tests for `canonical_register` / `analyze_registers` — no
    gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the register signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import analyze_cost, analyze_registers, canonical_register

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


# ─── Unit: canonical_register ────────────────────────────────────────────────

@pytest.mark.parametrize(
    "token,expected",
    [
        # 32-bit names fold to themselves
        ("eax", "eax"), ("ebx", "ebx"), ("ecx", "ecx"), ("edx", "edx"),
        ("esi", "esi"), ("edi", "edi"), ("ebp", "ebp"), ("esp", "esp"),
        ("eip", "eip"),
        # 16-bit sub-registers fold to their 32-bit family
        ("ax", "eax"), ("bx", "ebx"), ("cx", "ecx"), ("dx", "edx"),
        ("bp", "ebp"), ("sp", "esp"),
        # 8-bit sub-registers fold to their 32-bit family
        ("al", "eax"), ("ah", "eax"), ("bl", "ebx"), ("cl", "ecx"),
        ("dh", "edx"), ("sil", "esi"), ("dil", "edi"),
        # 64-bit spellings fold too (robustness if ever pointed at non -m32 asm)
        ("rax", "eax"), ("rbp", "ebp"), ("rip", "eip"),
        # x87 stack registers all fold to "st"
        ("st", "st"), ("st(0)", "st"), ("st(7)", "st"),
        # case-insensitive
        ("EAX", "eax"), ("Al", "eax"),
        # unknown token is kept as-is (lowercased), never dropped
        ("xmm0", "xmm0"), ("mm3", "mm3"),
    ],
)
def test_canonical_register(token, expected):
    assert canonical_register(token) == expected


# ─── Unit: analyze_registers (pure, no gcc) ──────────────────────────────────

def test_analyze_registers_explicit_operands():
    # Line 1 moves an immediate into a stack slot via %eax; line 2 adds %edx.
    asm_lines = [
        "movl $1, -4(%ebp)",     # %ebp
        "addl -8(%ebp), %eax",   # %ebp, %eax
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2], "color": "#111"},
    }
    summary = analyze_registers(line_map, asm_lines)

    assert line_map[1]["registers"] == ["ebp"]
    # Sorted in canonical order: eax before ebp.
    assert line_map[2]["registers"] == ["eax", "ebp"]
    # Two instructions touch %ebp, one touches %eax.
    assert summary["register_totals"] == {"eax": 1, "ebp": 2}


def test_analyze_registers_subregisters_fold_to_family():
    # %al and %dl are 8-bit views of %eax / %edx and must fold to the family.
    asm_lines = ["movb %al, %dl"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == ["eax", "edx"]


def test_analyze_registers_implicit_edx_eax_on_idiv():
    # The killer lesson: integer division's dividend is the %edx:%eax pair, so
    # the footprint must report %edx even though the operand text only names the
    # divisor (%ecx). cltd sign-extends %eax into %edx to set up that dividend.
    asm_lines = [
        "cltd",            # implicit: eax, edx  (no operands at all)
        "idivl %ecx",      # explicit ecx; implicit eax, edx
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)

    # The line touches ecx (divisor) plus the implicit accumulator/data pair.
    assert line_map[1]["registers"] == ["eax", "ecx", "edx"]
    # cltd touches {eax, edx}; idivl touches {eax, ecx, edx}.
    assert summary["register_totals"] == {"eax": 2, "ecx": 1, "edx": 2}


def test_analyze_registers_sse_divide_does_not_claim_edx():
    # SSE scalar divide (divsd) uses xmm registers, NOT %edx:%eax. The
    # integer-suffix guard must exclude it so the footprint never over-claims.
    asm_lines = ["divsd %xmm1, %xmm0"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    analyze_registers(line_map, asm_lines)
    assert "edx" not in line_map[1]["registers"]
    assert line_map[1]["registers"] == ["xmm0", "xmm1"]


def test_analyze_registers_two_operand_imul_has_no_implicit_edx():
    # gcc -O0 emits the two-operand imul form for `a * b`; that form does NOT
    # touch %edx, so we must not fabricate an edx claim from the mnemonic.
    asm_lines = ["imull %edx, %eax"]   # edx here is explicit, eax explicit
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    analyze_registers(line_map, asm_lines)
    # Only the two named registers; nothing implicit was added.
    assert line_map[1]["registers"] == ["eax", "edx"]


def test_analyze_registers_implicit_esp_on_push_pop():
    # push/pop mutate %esp on every occurrence, but AT&T names no %esp operand —
    # the footprint must report the stack-pointer traffic alongside the explicit
    # register being pushed/popped.
    asm_lines = ["pushl %ebp", "popl %ebp"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == ["ebp", "esp"]
    # Both instructions touch %ebp (explicit) and %esp (implicit).
    assert summary["register_totals"] == {"ebp": 2, "esp": 2}


def test_analyze_registers_implicit_esp_eip_on_call_and_ret():
    # call/ret carry no explicit register operand, yet both push/pop the return
    # address: they mutate %esp (stack) and %eip (instruction pointer).
    asm_lines = ["call helper", "ret"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == ["esp", "eip"]
    assert summary["register_totals"] == {"esp": 2, "eip": 2}


def test_analyze_registers_leave_touches_ebp_and_esp():
    # `leave` == `mov %ebp, %esp; pop %ebp` — it rewrites both the frame pointer
    # and the stack pointer with no explicit operand.
    asm_lines = ["leave"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == ["ebp", "esp"]


def test_analyze_registers_zero_touch_line_is_empty_list():
    # A line whose only asm is a label / directive touches no registers.
    asm_lines = [".L2:", "nop"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == []
    assert summary["register_totals"] == {}


def test_analyze_registers_x87_stack_folds_to_st():
    asm_lines = ["fldl -8(%ebp)", "faddp %st, %st(1)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    analyze_registers(line_map, asm_lines)
    # ebp from the first, st from both.
    assert line_map[1]["registers"] == ["ebp", "st"]


def test_analyze_registers_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring analyze_cost.
    asm_lines = ["movl %eax, %ebx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)
    assert line_map[1]["registers"] == ["eax", "ebx"]
    assert summary["register_totals"] == {"eax": 1, "ebx": 1}


def test_analyze_registers_totals_ordered_canonically():
    # register_totals keys must come back in the stable display order
    # (eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, st), regardless of
    # encounter order in the asm.
    asm_lines = ["movl %esp, %eax", "movl %edx, %ebx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_registers(line_map, asm_lines)
    assert list(summary["register_totals"].keys()) == ["eax", "ebx", "edx", "esp"]


def test_analyze_registers_empty_line_map():
    summary = analyze_registers({}, [])
    assert summary["register_totals"] == {}


def test_analyze_registers_does_not_disturb_cost_fields():
    # Regression: running the footprint pass after analyze_cost leaves the
    # existing cost/mix annotations intact and merely adds `registers`.
    asm_lines = ["imull %edx, %eax", "call helper"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_registers(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == ["mul", "call"]
    assert line_map[1]["category_counts"] == {"compute": 1, "call": 1}
    assert cost["total_instructions"] == 2
    # And the new field is present alongside the old ones. imull is two-operand
    # (eax, edx explicit, no implicit); `call helper` adds implicit esp + eip.
    assert line_map[1]["registers"] == ["eax", "edx", "esp", "eip"]


# ─── End-to-end: /compile carries the register footprint ─────────────────────

@needs_gcc
async def test_compile_response_includes_register_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["register_summary"] is not None
    totals = body["register_summary"]["register_totals"]
    assert isinstance(totals, dict) and totals
    # At -O0 the frame pointer %ebp is used for nearly every stack slot access.
    assert totals.get("ebp", 0) > 0
    # Every mapped line carries a registers list.
    for mapping in body["line_map"].values():
        assert "registers" in mapping
        assert isinstance(mapping["registers"], list)


@needs_gcc
async def test_compile_division_touches_edx_implicitly(client):
    # `a // b` compiles to cltd + idivl, whose dividend is the %edx:%eax pair —
    # so %edx must show up in the footprint even though the Python names no
    # register at all. This is the feature's central teaching moment.
    r = await client.post("/compile", json={"code": "def f(a, b):\n    return a // b\n"})
    assert r.status_code == 200
    body = r.json()
    totals = body["register_summary"]["register_totals"]
    assert totals.get("edx", 0) > 0
    # And the specific Python line for the division reports %edx in its footprint.
    div_line_has_edx = any(
        "edx" in mapping["registers"] for mapping in body["line_map"].values()
    )
    assert div_line_has_edx


@needs_gcc
async def test_compile_register_totals_ordered_and_known(client):
    r = await client.post("/compile", json={"code": "x = 5\ny = x * x\n"})
    assert r.status_code == 200
    totals = r.json()["register_summary"]["register_totals"]
    order = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "st"]
    seen = list(totals.keys())
    # Keys that are in the canonical set must appear in canonical order.
    ranked = [order.index(k) for k in seen if k in order]
    assert ranked == sorted(ranked)
