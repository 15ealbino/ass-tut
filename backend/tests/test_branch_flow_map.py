"""
Tests for the branch-flow-map feature (feat/branch-flow-map).

The branch flow map is the third per-line control-flow signal after the
instruction-mix "branch" bucket count and the register footprint. Where the
mix answers *how many* jumps a Python line emits and the footprint answers
*which registers* they touch, the branch map answers *which branches* —
naming each jump instruction, whether it's conditional, its target label,
and (critically for reading control flow off a disassembly) whether the
target lies above or below its source line.

Two layers, mirroring test_stack_frame_map.py / test_register_footprint.py:
  * Pure-function unit tests for `classify_branch` / `_label_positions` /
    `_parse_branch` / `branch_direction` / `analyze_branches` — no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc
    pipeline and assert the branch signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import (
    _label_positions,
    _parse_branch,
    analyze_branches,
    analyze_cost,
    branch_direction,
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


# ─── Unit: classify_branch ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "mnemonic,expected",
    [
        # Unconditional family
        ("jmp",   "unconditional"),
        ("jmpl",  "unconditional"),           # size-suffixed variant
        # Conditional j* family
        ("je",    "conditional"),
        ("jne",   "conditional"),
        ("jl",    "conditional"),
        ("jle",   "conditional"),
        ("jg",    "conditional"),
        ("jge",   "conditional"),
        ("ja",    "conditional"),
        ("jae",   "conditional"),
        ("jb",    "conditional"),
        ("jbe",   "conditional"),
        ("js",    "conditional"),
        ("jns",   "conditional"),
        ("jz",    "conditional"),
        ("jnz",   "conditional"),
        ("jecxz", "conditional"),
        # loop family
        ("loop",   "conditional"),
        ("loope",  "conditional"),
        ("loopne", "conditional"),
        # Non-branches
        ("mov",   None),
        ("movl",  None),
        ("call",  None),
        ("ret",   None),
        ("add",   None),
        ("cmp",   None),
        ("nop",   None),
        ("",      None),
    ],
)
def test_classify_branch(mnemonic, expected):
    assert classify_branch(mnemonic) == expected


# ─── Unit: _label_positions ───────────────────────────────────────────────────

def test_label_positions_maps_labels_to_display_line_numbers():
    asm_lines = [
        "main:",                    # line 1
        "\tpushl\t%ebp",            # line 2
        "\tmovl\t%esp, %ebp",       # line 3
        ".L2:",                     # line 4
        "\tmovl\t$1, -4(%ebp)",     # line 5
        ".L3:",                     # line 6
        "\tret",                    # line 7
    ]
    positions = _label_positions(asm_lines)
    assert positions == {"main": 1, ".L2": 4, ".L3": 6}


def test_label_positions_ignores_operand_mentions():
    # Only whole-line "label:" declarations count — a `jmp .L4` line does NOT
    # declare .L4, and if that operand mention were treated as a declaration
    # the direction pass would silently point every branch at itself.
    asm_lines = [
        "\tjmp\t.L4",           # operand mention, not a declaration
        "\tjle\t.L2",           # ditto
        ".L4:",                 # the real declaration
    ]
    positions = _label_positions(asm_lines)
    assert positions == {".L4": 3}


def test_label_positions_handles_dotted_and_hidden_labels():
    # gcc's `-g1` output carries `.LFB0`/`.LFE0` function-scope labels and
    # dotted symbol names (`__x86.get_pc_thunk.ax`); the pass must not drop them.
    asm_lines = [
        ".LFB0:",
        "\tpushl\t%ebp",
        ".LFE0:",
        "__x86.get_pc_thunk.ax:",
    ]
    positions = _label_positions(asm_lines)
    assert positions == {".LFB0": 1, ".LFE0": 3, "__x86.get_pc_thunk.ax": 4}


def test_label_positions_empty():
    assert _label_positions([]) == {}


# ─── Unit: _parse_branch ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # Common conditional/unconditional forms with a tab separator
        ("\tjle\t.L2",       ("jle", "conditional", ".L2")),
        ("\tjmp\t.L3",       ("jmp", "unconditional", ".L3")),
        ("\tjne\t.L5",       ("jne", "conditional", ".L5")),
        # Space separator, indented
        ("  je   .L4",       ("je", "conditional", ".L4")),
        # Indirect target: kept in the raw target string (starts with '*')
        ("\tjmp\t*%eax",     ("jmp", "unconditional", "*%eax")),
        # loop family
        ("\tloop\t.L6",      ("loop", "conditional", ".L6")),
    ],
)
def test_parse_branch_recognises_branches(text, expected):
    assert _parse_branch(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",                             # blank
        "\t",                           # whitespace only
        "main:",                        # label declaration
        ".L2:",                         # label declaration
        "\tmovl\t$1, -4(%ebp)",         # ordinary instruction
        "\tcmpl\t$0, %eax",             # cmp — feeds a branch but is not one
        "\tcall\tprintf",               # call is control flow but not a branch
        "\tret",                        # ret is control flow but not a branch
    ],
)
def test_parse_branch_rejects_non_branches(text):
    assert _parse_branch(text) is None


# ─── Unit: branch_direction ───────────────────────────────────────────────────

def test_branch_direction_forward_backward_and_self():
    labels = {".L2": 5, ".L3": 10, ".L4": 3}
    # Source 4, target .L2 at line 5 → target is AFTER → forward
    assert branch_direction(4, ".L2", labels) == "forward"
    # Source 12, target .L3 at line 10 → target is BEFORE → backward
    assert branch_direction(12, ".L3", labels) == "backward"
    # Source 5, target .L2 at line 5 → same line → self_loop
    assert branch_direction(5, ".L2", labels) == "self_loop"


def test_branch_direction_external_when_target_not_in_file():
    # An external tail call `jmp printf` where `printf` is never declared in
    # our compilation unit lands as "external", not "unknown" or a false hit.
    assert branch_direction(3, "printf", {}) == "external"


def test_branch_direction_unknown_for_indirect_or_missing_target():
    # `jmp *%eax` (indirect) and a malformed no-operand branch both classify
    # as "unknown" — the destination is not statically known from the operand.
    assert branch_direction(3, "*%eax", {".L2": 5}) == "unknown"
    assert branch_direction(3, "", {".L2": 5}) == "unknown"


# ─── Unit: analyze_branches (pure, no gcc) ────────────────────────────────────

def test_analyze_branches_if_else_forward_and_unconditional_skip():
    # Textbook if/else shape (gcc -O0 branch-around):
    #   cmpl $0, -4(%ebp)   (line 1)
    #   jle  .L2            (line 2)  conditional forward around the then-body
    #   movl $1, -4(%ebp)   (line 3)
    #   jmp  .L3            (line 4)  unconditional forward past the else-body
    # .L2:                  (line 5)
    #   movl $2, -4(%ebp)   (line 6)
    # .L3:                  (line 7)
    asm_lines = [
        "cmpl $0, -4(%ebp)",
        "jle .L2",
        "movl $1, -4(%ebp)",
        "jmp .L3",
        ".L2:",
        "movl $2, -4(%ebp)",
        ".L3:",
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},   # the if
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#000"},   # the then + jmp
        3: {"c_lines": [3], "asm_lines": [6], "color": "#000"},      # the else
    }
    summary = analyze_branches(line_map, asm_lines)

    assert line_map[1]["branches"] == [
        {"mnemonic": "jle", "conditional": True, "direction": "forward", "target": ".L2"},
    ]
    assert line_map[2]["branches"] == [
        {"mnemonic": "jmp", "conditional": False, "direction": "forward", "target": ".L3"},
    ]
    assert line_map[3]["branches"] == []

    assert summary["total"] == 2
    assert summary["conditional"] == 1
    assert summary["unconditional"] == 1
    assert summary["forward"] == 2
    assert summary["backward"] == 0
    assert summary["self_loop"] == 0
    assert summary["external"] == 0
    assert summary["unknown"] == 0


def test_analyze_branches_while_loop_backward_branch():
    # Textbook loop shape (gcc -O0):
    #   jmp .L4             (line 1) forward to the loop test
    # .L5:                  (line 2) loop body head
    #   addl $1, -4(%ebp)   (line 3)
    # .L4:                  (line 4) loop test head
    #   cmpl $9, -4(%ebp)   (line 5)
    #   jle .L5             (line 6) conditional BACKWARD back-edge
    asm_lines = [
        "jmp .L4",
        ".L5:",
        "addl $1, -4(%ebp)",
        ".L4:",
        "cmpl $9, -4(%ebp)",
        "jle .L5",
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 3, 5, 6], "color": "#000"},
    }
    summary = analyze_branches(line_map, asm_lines)

    # Two branches from this line: jmp forward to .L4, jle backward to .L5.
    assert line_map[1]["branches"] == [
        {"mnemonic": "jmp", "conditional": False, "direction": "forward", "target": ".L4"},
        {"mnemonic": "jle", "conditional": True, "direction": "backward", "target": ".L5"},
    ]
    assert summary["total"] == 2
    assert summary["conditional"] == 1
    assert summary["unconditional"] == 1
    assert summary["forward"] == 1
    assert summary["backward"] == 1


def test_analyze_branches_preserves_occurrence_order():
    # When a Python line's asm range contains multiple branches, the entries
    # come back in the same order they appear in the asm — not reordered by
    # mnemonic or by direction.
    asm_lines = [
        "je .L2",       # 1: conditional forward
        "jmp .L3",      # 2: unconditional forward
        ".L2:",         # 3
        ".L3:",         # 4
        "jmp .L2",      # 5: unconditional BACKWARD
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 5], "color": "#000"}}
    analyze_branches(line_map, asm_lines)
    mnemonics = [b["mnemonic"] for b in line_map[1]["branches"]]
    directions = [b["direction"] for b in line_map[1]["branches"]]
    assert mnemonics == ["je", "jmp", "jmp"]
    assert directions == ["forward", "forward", "backward"]


def test_analyze_branches_external_target():
    # A `jmp printf` (tail call) whose label isn't declared in this file
    # lands as "external", not as an accidental "unknown" or self-loop.
    asm_lines = ["jmp printf"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branches"] == [
        {"mnemonic": "jmp", "conditional": False, "direction": "external", "target": "printf"},
    ]
    assert summary["external"] == 1


def test_analyze_branches_indirect_target_is_unknown():
    asm_lines = ["jmp *%eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branches"] == [
        {"mnemonic": "jmp", "conditional": False, "direction": "unknown", "target": "*%eax"},
    ]
    assert summary["unknown"] == 1


def test_analyze_branches_ignores_non_branches():
    # A line whose asm is all mov/add/cmp/ret contributes no branches.
    asm_lines = [
        "movl $1, %eax",
        "addl %edx, %eax",
        "cmpl $0, %eax",
        "call printf",
        "ret",
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2, 3, 4, 5], "color": "#000"},
    }
    summary = analyze_branches(line_map, asm_lines)
    assert line_map[1]["branches"] == []
    assert summary["total"] == 0


def test_analyze_branches_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring the
    # other per-line passes.
    asm_lines = ["jmp .L2", ".L2:"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_branches(line_map, asm_lines)
    assert len(line_map[1]["branches"]) == 1
    assert summary["total"] == 1


def test_analyze_branches_empty_line_map():
    summary = analyze_branches({}, [])
    assert summary == {
        "total": 0, "conditional": 0, "unconditional": 0,
        "forward": 0, "backward": 0, "self_loop": 0,
        "external": 0, "unknown": 0,
    }


def test_analyze_branches_does_not_disturb_cost_fields():
    # Regression: running the branch pass after analyze_cost leaves the
    # existing cost/mix annotations intact and merely adds `branches`.
    asm_lines = ["cmpl $0, %eax", "jle .L2", ".L2:"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_branches(line_map, asm_lines)
    assert line_map[1]["asm_count"] == 2
    # cmp → branch bucket; jle → branch bucket. Both count under "branch".
    assert line_map[1]["category_counts"] == {"branch": 2}
    assert cost["total_instructions"] == 2
    # The new field is present alongside the old ones.
    assert line_map[1]["branches"] == [
        {"mnemonic": "jle", "conditional": True, "direction": "forward", "target": ".L2"},
    ]


def test_analyze_branches_totals_sum_matches_per_line_entries():
    # The per-line branch entries and the summary totals must agree — if they
    # drift, downstream UIs would show inconsistent counts.
    asm_lines = [
        "je .L2",       # 1: conditional forward
        "jmp .L3",      # 2: unconditional forward
        ".L2:",         # 3
        "jmp .L2",      # 4: unconditional BACKWARD
        ".L3:",         # 5
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2, 4], "color": "#000"},
    }
    summary = analyze_branches(line_map, asm_lines)
    per_line_total = sum(len(m["branches"]) for m in line_map.values())
    assert per_line_total == summary["total"] == 3
    directions = [
        b["direction"] for m in line_map.values() for b in m["branches"]
    ]
    assert (
        directions.count("forward") == summary["forward"]
        and directions.count("backward") == summary["backward"]
    )


# ─── End-to-end: /compile carries the branch flow map ────────────────────────

@needs_gcc
async def test_compile_response_includes_branch_summary(client):
    # A trivial straight-line program still emits at least the function
    # epilogue's `ret` — but not a *branch* (ret is call-family, not a
    # branch). So we compile a program with an explicit conditional and
    # assert both the per-line entries and the summary carry it.
    code = "x = 0\nif x > 0:\n    x = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    assert body["branch_summary"] is not None
    bs = body["branch_summary"]
    # At least the conditional forward jump generated by the if.
    assert bs["total"] >= 1
    assert bs["conditional"] >= 1
    assert bs["forward"] >= 1
    # Every mapped line carries a branches list (possibly empty).
    for mapping in body["line_map"].values():
        assert "branches" in mapping
        assert isinstance(mapping["branches"], list)


@needs_gcc
async def test_compile_while_loop_produces_backward_branch(client):
    # A while loop's back-edge is the canonical backward branch. If our pass
    # were mis-oriented (labelling by source-vs-target the wrong way round),
    # this test would flip.
    code = "i = 0\nwhile i < 5:\n    i += 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    bs = body["branch_summary"]
    assert bs["backward"] >= 1, (
        f"expected a backward branch for the while loop, got summary {bs}"
    )
    # The per-line entries must also reflect the same shape.
    all_branches = [
        b for m in body["line_map"].values() for b in m["branches"]
    ]
    assert any(b["direction"] == "backward" for b in all_branches)


@needs_gcc
async def test_compile_if_produces_forward_conditional_branch(client):
    # An if with no matching else still produces a forward conditional
    # branch — the branch-around-the-then-body pattern.
    code = "x = 3\nif x > 0:\n    x = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    all_branches = [
        b for m in body["line_map"].values() for b in m["branches"]
    ]
    assert any(
        b["conditional"] and b["direction"] == "forward" for b in all_branches
    ), f"expected a conditional forward branch, got: {all_branches}"


@needs_gcc
async def test_compile_branches_carry_expected_fields(client):
    # Structural check on every emitted per-line branch entry, so a schema
    # drift would be caught here rather than downstream in the UI.
    code = "x = 0\nif x > 0:\n    x = 1\nelse:\n    x = 2\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    for mapping in body["line_map"].values():
        for br in mapping["branches"]:
            assert set(br.keys()) == {"mnemonic", "conditional", "direction", "target"}
            assert isinstance(br["mnemonic"], str) and br["mnemonic"]
            assert isinstance(br["conditional"], bool)
            assert br["direction"] in (
                "forward", "backward", "self_loop", "external", "unknown",
            )
            assert isinstance(br["target"], str)
