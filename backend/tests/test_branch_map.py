"""
Tests for the branch-condition map feature (feat/asm-branch-map).

Where the instruction mix lumps every jump into a single "branch" bucket and the
glossary describes a conditional jump generically, this feature classifies each
jump by *sense* — signed (jl/jle/jg/jge), unsigned (jb/jbe/ja/jae), equality
(je/jne), or the unconditional jmp. The lesson (mission pillar 2) is that x86 has
two parallel jump families testing the same compare, and picking the wrong one is
a textbook vulnerability: a signed length read through an unsigned branch (or the
reverse) slips a negative/huge value straight past a bounds check. This
transpiler emits all-`int` C, so gcc emits the SIGNED family — the feature makes
that concrete and trains the eye to spot an unexpected unsigned branch.

Two layers, mirroring test_memory_traffic.py / test_register_footprint.py:
  * Pure-function unit tests for `classify_branch` / `analyze_branches` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the branch signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32) is missing, so the
suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import (
    analyze_branches,
    analyze_cost,
    classify_branch,
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


# ─── Unit: classify_branch (pure, no gcc) ────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # ── the unconditional jump ──
        ("jmp", "unconditional"),
        # ── equality (sense-neutral) ──
        ("je", "equality"), ("jz", "equality"),
        ("jne", "equality"), ("jnz", "equality"),
        # ── signed ordering (the family gcc emits for int comparisons) ──
        ("jl", "signed"), ("jle", "signed"), ("jg", "signed"), ("jge", "signed"),
        ("jnge", "signed"), ("jng", "signed"), ("jnle", "signed"), ("jnl", "signed"),
        ("js", "signed"), ("jns", "signed"),
        # ── unsigned ordering (the bug signal — should not appear for int C) ──
        ("jb", "unsigned"), ("jbe", "unsigned"), ("ja", "unsigned"), ("jae", "unsigned"),
        ("jnae", "unsigned"), ("jna", "unsigned"), ("jnbe", "unsigned"), ("jnb", "unsigned"),
        ("jc", "unsigned"), ("jnc", "unsigned"),
        # ── overflow / parity — real branches, but neither ordering nor equality ──
        ("jo", "other"), ("jno", "other"), ("jp", "other"),
        ("jpe", "other"), ("jnp", "other"), ("jpo", "other"),
        # ── non-branch mnemonics classify as None (ignored, not bucketed) ──
        ("movl", None), ("call", None), ("cmpl", None), ("leave", None),
        ("ret", None), ("push", None), ("", None),
        # ── a bare `j` is not a real mnemonic and must not match a family ──
        ("j", None),
    ],
)
def test_classify_branch(mnemonic, expected):
    assert classify_branch(mnemonic) == expected


def test_signed_and_unsigned_families_are_disjoint():
    # A defensive invariant: no jump mnemonic is classified as both signed and
    # unsigned. Confusing the two IS the vulnerability the feature teaches, so
    # the classifier must never blur them.
    from app.compile import _SIGNED_JUMPS, _UNSIGNED_JUMPS, _EQUALITY_JUMPS
    assert _SIGNED_JUMPS.isdisjoint(_UNSIGNED_JUMPS)
    assert _SIGNED_JUMPS.isdisjoint(_EQUALITY_JUMPS)
    assert _UNSIGNED_JUMPS.isdisjoint(_EQUALITY_JUMPS)


# ─── Unit: analyze_branches (pure, no gcc) ───────────────────────────────────

def test_analyze_branches_counts_per_line_and_totals():
    # A `while i < n:` loop lowering: a compare + a signed jump back, plus the
    # unconditional jump to the loop condition.
    asm_lines = [
        "jmp .L2",               # unconditional jump to the condition
        "cmpl -8(%ebp), %eax",   # not a branch (the compare it feeds)
        "jl .L3",                # signed jump-if-less back into the body
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)

    assert line_map[1]["branch_counts"] == {"signed": 1, "unconditional": 1}
    assert summary["branch_totals"] == {"signed": 1, "unconditional": 1}


def test_analyze_branches_zero_entries_omitted_per_line():
    # A line with no jumps reports an empty per-line map (mirrors the mix's
    # zero-omission); a program with no jumps yields empty totals.
    asm_lines = ["movl %eax, %ebx", "cmpl $0, -4(%ebp)"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)

    assert line_map[1]["branch_counts"] == {}
    assert summary["branch_totals"] == {}


def test_analyze_branches_orders_senses_for_stable_display():
    # equality after signed after nothing: keys come back in _BRANCH_ORDER, not
    # insertion order, so the chip/tooltip render deterministically.
    asm_lines = ["je .L1", "jl .L2", "jmp .L3"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    analyze_branches(line_map, asm_lines)
    assert list(line_map[1]["branch_counts"].keys()) == [
        "signed", "equality", "unconditional",
    ]


def test_analyze_branches_totals_sum_across_lines():
    asm_lines = [
        "jl .L1",     # line 1: signed
        "jmp .L2",    # line 1: unconditional
        "je .L3",     # line 2: equality
        "jge .L4",    # line 2: signed
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#111"},
    }
    summary = analyze_branches(line_map, asm_lines)

    assert line_map[1]["branch_counts"] == {"signed": 1, "unconditional": 1}
    assert line_map[2]["branch_counts"] == {"signed": 1, "equality": 1}
    # 2 signed (1+1), 1 equality, 1 unconditional program-wide.
    assert summary["branch_totals"] == {"signed": 2, "equality": 1, "unconditional": 1}


def test_analyze_branches_detects_unsigned_branch():
    # The headline lesson: an UNSIGNED branch is surfaced distinctly from a
    # signed one. gcc won't emit this for the transpiler's int-only C, but the
    # analyzer must flag it if it ever appears (the comparison-safety signal).
    asm_lines = ["jb .L1", "ja .L2"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branch_counts"] == {"unsigned": 2}
    assert summary["branch_totals"] == {"unsigned": 2}


def test_analyze_branches_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring analyze_cost.
    asm_lines = ["jl .L1"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branch_counts"] == {"signed": 1}
    assert summary["branch_totals"] == {"signed": 1}


def test_analyze_branches_empty_line_map():
    summary = analyze_branches({}, [])
    assert summary["branch_totals"] == {}


def test_analyze_branches_does_not_disturb_cost_fields():
    # Regression: running the branch pass after analyze_cost leaves the existing
    # cost/mix annotations intact and merely adds `branch_counts`. Note the jump
    # still counts toward the instruction total and the "branch" mix bucket — the
    # new field refines the mix, it does not replace it.
    asm_lines = ["cmpl $0, -4(%ebp)", "jle .L2"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_branches(line_map, asm_lines)

    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["category_counts"] == {"branch": 2}
    assert cost["total_instructions"] == 2
    assert line_map[1]["branch_counts"] == {"signed": 1}


# ─── End-to-end: /compile carries the branch summary ─────────────────────────

@needs_gcc
async def test_compile_response_includes_branch_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["branch_summary"] is not None
    assert "branch_totals" in body["branch_summary"]
    # Every mapped line carries a branch_counts map (possibly empty).
    for mapping in body["line_map"].values():
        assert "branch_counts" in mapping
        assert isinstance(mapping["branch_counts"], dict)


@needs_gcc
async def test_compile_loop_emits_signed_branches(client):
    # A `for i in range(n)` loop compiles to an `int` comparison, which gcc
    # lowers to a SIGNED conditional jump. The program must therefore show
    # signed branch traffic and no unsigned branches (the feature's core claim).
    code = "total = 0\nfor i in range(10):\n    total += i\nprint(total)\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["branch_summary"]["branch_totals"]
    assert totals.get("signed", 0) > 0
    # int comparisons never lower to unsigned branches — that is the whole point.
    assert totals.get("unsigned", 0) == 0


@needs_gcc
async def test_compile_if_equality_branch(client):
    # `if a == b:` lowers to a compare + an equality jump (je/jne). The program
    # must show equality branch traffic distinct from ordering branches.
    code = "a = 3\nb = 3\nif a == b:\n    a = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    totals = r.json()["branch_summary"]["branch_totals"]
    assert totals.get("equality", 0) > 0


@needs_gcc
async def test_compile_straightline_has_no_conditional_branches(client):
    # Straight-line code with no control flow produces no conditional jumps, so
    # branch_totals carries no signed/unsigned/equality entries (an unconditional
    # jmp may still appear around main's epilogue, so we only assert the
    # conditional senses are absent).
    r = await client.post("/compile", json={"code": "a = 1\nb = 2\nc = a + b\n"})
    assert r.status_code == 200
    totals = r.json()["branch_summary"]["branch_totals"]
    assert totals.get("signed", 0) == 0
    assert totals.get("unsigned", 0) == 0
    assert totals.get("equality", 0) == 0
