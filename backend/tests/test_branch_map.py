"""
Tests for the control-flow branch-map feature (feat/branch-map).

Where the cost/mix passes count instructions and the register/stack/memory passes
say *where data lives*, the branch map says *where control goes*: the jump
instructions each Python line emits, each jump's target label, and — the teaching
payload — whether it is a BACKWARD jump (a loop back-edge, how for/while repeat)
or a FORWARD jump (skipping code, how if/elif/else, break and short-circuit
and/or bail out).

Two layers, mirroring test_instruction_mix.py / test_memory_traffic.py:
  * Pure-function unit tests for `_jump_kind`, `_collect_labels`, `_branch_at`,
    and `analyze_branches` — no gcc, using hand-written asm that matches the shape
    gcc -O0 actually emits (labels at column 0, jumps as indented instructions).
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the branch signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32) is missing, so the
suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import (
    _branch_at,
    _collect_labels,
    _jump_kind,
    analyze_branches,
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


# ─── Unit: _jump_kind ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # unconditional jump (and size-suffixed forms)
        ("jmp", "uncond"),
        ("jmpl", "uncond"),
        # conditional jumps — the whole je/jne/jl/jle/jg/jge/js/… family
        ("je", "cond"),
        ("jne", "cond"),
        ("jl", "cond"),
        ("jle", "cond"),
        ("jg", "cond"),
        ("jge", "cond"),
        ("js", "cond"),
        ("jns", "cond"),
        ("ja", "cond"),
        ("jae", "cond"),
        ("jb", "cond"),
        ("jbe", "cond"),
        ("jz", "cond"),
        ("jnz", "cond"),
        ("jecxz", "cond"),
        # loop family branches on %ecx — conditional
        ("loop", "cond"),
        ("loope", "cond"),
        ("loopne", "cond"),
        # not jumps — must return None (call in particular is not a branch here)
        ("call", None),
        ("calll", None),
        ("movl", None),
        ("addl", None),
        ("leave", None),
        ("ret", None),
        ("", None),
    ],
)
def test_jump_kind(mnemonic, expected):
    assert _jump_kind(mnemonic) == expected


# ─── Unit: _collect_labels ───────────────────────────────────────────────────

def test_collect_labels_maps_name_to_line():
    asm_lines = [
        "\tpushl %ebp",     # 1 — instruction
        ".L2:",             # 2 — label
        "\tmovl $0, %eax",  # 3
        ".L3:",             # 4 — label
        "main:",            # 5 — function label (no leading dot)
    ]
    labels = _collect_labels(asm_lines)
    assert labels == {".L2": 2, ".L3": 4, "main": 5}


def test_collect_labels_first_definition_wins():
    # Defensive: if a label somehow appears twice, the earlier line is kept.
    asm_lines = [".L2:", "\tnop", ".L2:"]
    assert _collect_labels(asm_lines)[".L2"] == 1


def test_collect_labels_ignores_directives_and_instructions():
    asm_lines = ["\t.cfi_startproc", "\tmovl %eax, %ebx", "\t.text"]
    assert _collect_labels(asm_lines) == {}


# ─── Unit: _branch_at ────────────────────────────────────────────────────────

def test_branch_at_forward_conditional():
    labels = {".L3": 10}
    edge = _branch_at("\tjle .L3", 5, labels)
    assert edge == {
        "mnemonic": "jle",
        "target": ".L3",
        "direction": "forward",
        "conditional": True,
    }


def test_branch_at_backward_is_loop_edge():
    labels = {".L4": 3}
    edge = _branch_at("\tjl .L4", 12, labels)
    assert edge["direction"] == "back"
    assert edge["conditional"] is True


def test_branch_at_unconditional_jmp():
    labels = {".L2": 20}
    edge = _branch_at("\tjmp .L2", 8, labels)
    assert edge["mnemonic"] == "jmp"
    assert edge["conditional"] is False
    assert edge["direction"] == "forward"


def test_branch_at_target_at_same_line_counts_as_back():
    # A target defined at or before the jump is a back-edge (<=). Equality cannot
    # occur in practice (a jump line is not a label) but the boundary is defined.
    assert _branch_at("\tjmp .L1", 4, {".L1": 4})["direction"] == "back"


def test_branch_at_indirect_jump():
    edge = _branch_at("\tjmp *%eax", 5, {})
    assert edge["direction"] == "indirect"
    assert edge["target"] == "*%eax"
    assert edge["conditional"] is False


def test_branch_at_unknown_label():
    # A label target not present in the emitted asm is flagged, never guessed.
    edge = _branch_at("\tje .Lmissing", 5, {".L2": 1})
    assert edge["direction"] == "unknown"


@pytest.mark.parametrize(
    "line",
    [
        "",                       # blank
        "\tmovl %eax, -4(%ebp)",  # non-jump instruction
        "\tcall helper",          # call is not a branch
        ".L2:",                   # label line
        "\t.cfi_endproc",         # directive
    ],
)
def test_branch_at_returns_none_for_non_jumps(line):
    assert _branch_at(line, 1, {".L2": 1}) is None


# ─── Unit: analyze_branches (pure, no gcc) ───────────────────────────────────

# A hand-written asm block matching the shape gcc -O0 emits for a `while` loop
# that contains an `if` — the exact structure verified against real gcc output:
#   line 1: jmp .L2      (forward, to the loop test)
#   line 2: .L4:         (loop body label)
#   line 3: jle .L3      (forward, the if-condition skip)
#   line 4: .L3:
#   line 5: .L2:         (loop test label)
#   line 6: jl .L4       (backward — the loop back-edge)
_LOOP_ASM = [
    "\tjmp .L2",   # 1
    ".L4:",        # 2
    "\tjle .L3",   # 3
    ".L3:",        # 4
    ".L2:",        # 5
    "\tjl .L4",    # 6
]


def test_analyze_branches_annotates_and_summarises_a_loop():
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 6], "color": "#000"},  # loop header
        2: {"c_lines": [2], "asm_lines": [3], "color": "#111"},     # if condition
    }
    summary = analyze_branches(line_map, _LOOP_ASM)

    # Loop header line owns the forward jmp-to-test and the backward loop edge.
    assert line_map[1]["branches"] == [
        {"mnemonic": "jmp", "target": ".L2", "direction": "forward", "conditional": False},
        {"mnemonic": "jl", "target": ".L4", "direction": "back", "conditional": True},
    ]
    # If line owns the forward conditional skip.
    assert line_map[2]["branches"] == [
        {"mnemonic": "jle", "target": ".L3", "direction": "forward", "conditional": True},
    ]

    assert summary == {
        "total_jumps": 3,
        "conditional": 2,
        "unconditional": 1,
        "back_edges": 1,     # exactly one loop
        "forward_edges": 2,
    }


def test_analyze_branches_conditional_plus_unconditional_equals_total():
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 3, 6], "color": "#000"}}
    s = analyze_branches(line_map, _LOOP_ASM)
    assert s["conditional"] + s["unconditional"] == s["total_jumps"]


def test_analyze_branches_line_with_no_jumps_gets_empty_list():
    asm_lines = ["\tmovl $1, -4(%ebp)", "\taddl $2, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branches"] == []
    assert summary["total_jumps"] == 0
    assert summary["back_edges"] == 0


def test_analyze_branches_ignores_out_of_range_asm_index():
    # A stray asm index past the end is skipped, never crashes or miscounts.
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_branches(line_map, _LOOP_ASM)
    assert line_map[1]["branches"] == [
        {"mnemonic": "jmp", "target": ".L2", "direction": "forward", "conditional": False},
    ]
    assert summary["total_jumps"] == 1


def test_analyze_branches_empty_line_map():
    summary = analyze_branches({}, [])
    assert summary == {
        "total_jumps": 0,
        "conditional": 0,
        "unconditional": 0,
        "back_edges": 0,
        "forward_edges": 0,
    }


def test_analyze_branches_only_adds_branches_field():
    # Regression: the pass must not disturb fields other passes own.
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#abc"}}
    analyze_branches(line_map, _LOOP_ASM)
    assert line_map[1]["c_lines"] == [1]
    assert line_map[1]["color"] == "#abc"
    assert "branches" in line_map[1]


# ─── End-to-end: /compile carries the branch signal ──────────────────────────

@needs_gcc
async def test_compile_response_includes_branch_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    bs = body["branch_summary"]
    assert bs is not None
    # Every mapped line carries a branches list (possibly empty).
    for mapping in body["line_map"].values():
        assert "branches" in mapping
        assert isinstance(mapping["branches"], list)
    # conditional + unconditional always accounts for every jump.
    assert bs["conditional"] + bs["unconditional"] == bs["total_jumps"]


@needs_gcc
async def test_compile_straight_line_has_no_back_edges(client):
    # No loops → no back-edges.
    r = await client.post("/compile", json={"code": "x = 1\ny = 2\nz = x + y\n"})
    assert r.status_code == 200
    assert r.json()["branch_summary"]["back_edges"] == 0


@needs_gcc
async def test_compile_loop_produces_a_back_edge(client):
    # A `for`/`while` loop must compile to at least one backward jump (the
    # back-edge that makes the CPU repeat the body).
    code = "x = 0\nfor i in range(5):\n    x = x + i\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    bs = r.json()["branch_summary"]
    assert bs["back_edges"] >= 1
    # At least one Python line must carry a "back" branch edge.
    edges = [
        e
        for m in r.json()["line_map"].values()
        for e in m["branches"]
    ]
    assert any(e["direction"] == "back" for e in edges)


@needs_gcc
async def test_compile_if_produces_a_forward_conditional(client):
    # An `if` compiles to a forward conditional jump that skips the body.
    code = "x = 5\nif x > 2:\n    x = x + 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    bs = r.json()["branch_summary"]
    assert bs["forward_edges"] >= 1
    assert bs["conditional"] >= 1


@needs_gcc
async def test_compile_transpile_error_still_422(client):
    # A construct the transpiler rejects returns HTTP 422 (branch map never runs).
    r = await client.post("/compile", json={"code": "import os\n"})
    assert r.status_code == 422
