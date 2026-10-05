"""
Tests for the loop-depth-map feature (feat/loop-depth-map).

Where the branch-flow map names each backward branch, this pass turns those
back-edges into structure: it recovers the loop nest and attributes a loop
DEPTH to every Python line — the run-count multiplier the cost/cycle passes
omit (a costly line at depth 2 runs outer × inner times).

Two layers, mirroring test_branch_flow_map.py / test_strength_hints.py:
  * Pure-function unit tests for `branch_target` / `loop_spans` / `depth_at` /
    `analyze_loops` — no gcc, no real assembly needed (synthetic asm snippets).
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert both that the summary reaches the API and that the depth the pass
    reports matches the loop structure gcc actually emits (grounded against the
    branch-flow map's back-edge count).

The e2e tests are skipped automatically if gcc (with -m32) is missing, so the
suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.loops import (
    analyze_loops,
    branch_target,
    depth_at,
    loop_spans,
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


# ─── Synthetic asm snippets (1-indexed when passed as a list) ────────────────
#
# A single loop at gcc -O0: jump-to-test at the top, body, test, backward branch.
#   1 main:
#   2   jmp .L2        ← forward (to the test) — NOT a loop edge
#   3 .L3:             ← loop-body head  (span start)
#   4   <body>
#   5 .L2:             ← loop test
#   6   cmpl ...
#   7   jle .L3        ← BACKWARD branch (span end)  → span (3, 7)
#   8   ret
_SINGLE_LOOP = [
    "main:",
    "\tjmp .L2",
    ".L3:",
    "\tmovl $1, -4(%ebp)",
    ".L2:",
    "\tcmpl $4, -8(%ebp)",
    "\tjle .L3",
    "\tret",
]

# Two nested loops: inner back-edge (6, 10), outer back-edge (3, 13).
#   1   movl $0, -4(%ebp)   # i = 0            (outside every loop)
#   2   jmp .L2             # forward (outer test)
#   3 .L3:                  # outer body head  (outer span start)
#   4   movl $0, -8(%ebp)   # j = 0
#   5   jmp .L4             # forward (inner test)
#   6 .L5:                  # inner body head  (inner span start)
#   7   addl $1, -12(%ebp)  # body             (depth 2)
#   8 .L4:                  # inner test
#   9   cmpl $2, -8(%ebp)
#  10   jle .L5             # BACKWARD (inner)  → span (6, 10)
#  11 .L2:                  # outer test
#  12   cmpl $2, -4(%ebp)
#  13   jle .L3             # BACKWARD (outer)  → span (3, 13)
#  14   ret
_NESTED_LOOPS = [
    "\tmovl $0, -4(%ebp)",
    "\tjmp .L2",
    ".L3:",
    "\tmovl $0, -8(%ebp)",
    "\tjmp .L4",
    ".L5:",
    "\taddl $1, -12(%ebp)",
    ".L4:",
    "\tcmpl $2, -8(%ebp)",
    "\tjle .L5",
    ".L2:",
    "\tcmpl $2, -4(%ebp)",
    "\tjle .L3",
    "\tret",
]

# A single `while` with a compound `or` condition. At gcc -O0 each short-circuited
# disjunct is its own conditional backward branch to the SAME body label, so the
# loop has TWO back-edges to `.L3` — yet it is still ONE non-nested loop. (Shape
# verified against real `gcc -S -O0` for `while (a < 5 || b < 3) { ... }`.)
#   3 .L3:               # body head          (the one loop's span start)
#   4   <body>           #                     depth 1
#   5 .L2:               # test
#   6   cmpl $4, -4(%ebp)
#   7   jle .L3          # BACKWARD (a < 5)   → back-edge 1 to .L3
#   8   cmpl $2, -8(%ebp)
#   9   jle .L3          # BACKWARD (b < 3)   → back-edge 2 to .L3
#  10   ret
_OR_LOOP = [
    "main:",
    "\tjmp .L2",
    ".L3:",
    "\taddl $1, -12(%ebp)",
    ".L2:",
    "\tcmpl $4, -4(%ebp)",
    "\tjle .L3",
    "\tcmpl $2, -8(%ebp)",
    "\tjle .L3",
    "\tret",
]


# ─── Unit: branch_target (pure, no gcc) ──────────────────────────────────────

@pytest.mark.parametrize(
    "line,expected",
    [
        ("\tjmp .L2", ".L2"),
        ("\tjmpl .L2", ".L2"),
        ("\tjle .L3", ".L3"),
        ("\tjne .L7", ".L7"),
        ("\tloop .L4", ".L4"),
        ("    je   .L10   ", ".L10"),   # extra whitespace tolerated
    ],
)
def test_branch_target_extracts_label(line, expected):
    assert branch_target(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "\tmovl $1, -4(%ebp)",   # not a branch
        "\tcall printf",         # call is not a loop branch
        "\tret",                 # ret is not a loop branch
        "\tcmpl $0, %eax",       # compare, not a branch
        ".L2:",                  # a label declaration, not a branch
        "\tjmp *%eax",           # indirect target — no static label
        "\tjmp",                 # operand-less / malformed
        "",                      # blank
    ],
)
def test_branch_target_none_for_non_branch(line):
    assert branch_target(line) is None


# ─── Unit: loop_spans (pure, no gcc) ─────────────────────────────────────────

def test_loop_spans_single_loop():
    # Only the backward branch is a loop edge; the leading `jmp .L2` is forward.
    assert loop_spans(_SINGLE_LOOP) == [(3, 7)]


def test_loop_spans_nested_loops():
    # Inner back-edge first (it occurs first in the stream), then the outer.
    assert loop_spans(_NESTED_LOOPS) == [(6, 10), (3, 13)]


def test_loop_spans_merges_multiple_back_edges_to_one_head():
    # Regression: a `while a or b` loop has TWO back-edges to the same body
    # label but is ONE loop. loop_spans must dedupe by target label into a
    # single span (head → the LAST back-edge), not report two overlapping spans
    # that would miscount the depth as 2.
    assert loop_spans(_OR_LOOP) == [(3, 9)]


def test_loop_spans_forward_only_has_no_loops():
    # A plain if/else: a conditional forward jump around the then-body and an
    # unconditional forward jump past the else. No target sits above its branch.
    asm = [
        "\tcmpl $0, -4(%ebp)",
        "\tjle .L2",     # forward (target .L2 below)
        "\tmovl $1, -4(%ebp)",
        "\tjmp .L3",     # forward (target .L3 below)
        ".L2:",
        "\tmovl $2, -4(%ebp)",
        ".L3:",
        "\tret",
    ]
    assert loop_spans(asm) == []


def test_loop_spans_excludes_external_target():
    # A tail-call-style `jmp printf` whose label is not declared in the file is
    # not an intra-file back-edge even though `printf:` is absent.
    asm = ["\tmovl $1, %eax", "\tjmp printf"]
    assert loop_spans(asm) == []


def test_loop_spans_empty_input():
    assert loop_spans([]) == []


# ─── Unit: depth_at (pure, no gcc) ───────────────────────────────────────────

def test_depth_at_single_loop():
    spans = loop_spans(_SINGLE_LOOP)
    assert depth_at(2, spans) == 0    # the forward jmp, above the body head
    assert depth_at(4, spans) == 1    # the body
    assert depth_at(7, spans) == 1    # the back-edge itself is in its own loop
    assert depth_at(8, spans) == 0    # ret, past the loop


def test_depth_at_nested_loops():
    spans = loop_spans(_NESTED_LOOPS)
    assert depth_at(1, spans) == 0    # i = 0, outside every loop
    assert depth_at(7, spans) == 2    # inner body — inside both loops
    assert depth_at(10, spans) == 2   # inner back-edge — still inside both
    assert depth_at(13, spans) == 1   # outer back-edge — outer loop only


# ─── Unit: analyze_loops (pure, no gcc) ──────────────────────────────────────

def _line_map(mapping):
    """Build a line_map from {py_line: [asm_line, ...]} with filler fields."""
    return {
        py: {"c_lines": [py], "asm_lines": list(asm), "color": "#000"}
        for py, asm in mapping.items()
    }


def test_analyze_loops_annotates_depth_and_summary_single():
    # py1 → the body (asm 4, depth 1); py2 → ret (asm 8, depth 0).
    line_map = _line_map({1: [4], 2: [8]})
    summary = analyze_loops(line_map, _SINGLE_LOOP)

    assert line_map[1]["loop_depth"] == 1
    assert line_map[2]["loop_depth"] == 0
    assert summary["loop_count"] == 1
    assert summary["max_depth"] == 1
    assert summary["hotspots"] == [{"py_line": 1, "loop_depth": 1}]


def test_analyze_loops_takes_max_over_mapped_asm_lines():
    # A loop-header line maps to both outside (init) and inside (test) asm; the
    # reported depth is the max — the line's condition re-runs every iteration.
    line_map = _line_map({1: [2, 6, 7]})  # forward jmp (0) + test (1) + edge (1)
    analyze_loops(line_map, _SINGLE_LOOP)
    assert line_map[1]["loop_depth"] == 1


def test_analyze_loops_nested_depths_and_summary():
    # py1 → outside; py2 → outer body/test; py3 → inner body (depth 2).
    line_map = _line_map({1: [1], 2: [12, 13], 3: [7]})
    summary = analyze_loops(line_map, _NESTED_LOOPS)

    assert line_map[1]["loop_depth"] == 0
    assert line_map[2]["loop_depth"] == 1
    assert line_map[3]["loop_depth"] == 2
    assert summary["loop_count"] == 2
    assert summary["max_depth"] == 2
    # Deepest first, then by line number.
    assert summary["hotspots"] == [
        {"py_line": 3, "loop_depth": 2},
        {"py_line": 2, "loop_depth": 1},
    ]


def test_analyze_loops_compound_or_condition_is_one_depth_one_loop():
    # The payoff of the dedup: a single `while a or b` loop reports loop_count 1
    # and max_depth 1, and its body line is depth 1 — not 2.
    line_map = _line_map({1: [4]})   # py1 → the loop body (asm line 4)
    summary = analyze_loops(line_map, _OR_LOOP)
    assert line_map[1]["loop_depth"] == 1
    assert summary["loop_count"] == 1
    assert summary["max_depth"] == 1
    assert summary["hotspots"] == [{"py_line": 1, "loop_depth": 1}]


def test_analyze_loops_no_loops_gives_zero_summary():
    line_map = _line_map({1: [1], 2: [2]})
    asm = ["\tmovl $1, -4(%ebp)", "\tret"]
    summary = analyze_loops(line_map, asm)
    assert line_map[1]["loop_depth"] == 0
    assert line_map[2]["loop_depth"] == 0
    assert summary == {"loop_count": 0, "max_depth": 0, "hotspots": []}


def test_analyze_loops_max_depth_independent_of_line_map():
    # The deepest instruction (asm 7) is not mapped to any Python line, yet
    # max_depth still reports 2 — it is read off the spans, not the mappings.
    line_map = _line_map({1: [1]})
    summary = analyze_loops(line_map, _NESTED_LOOPS)
    assert line_map[1]["loop_depth"] == 0
    assert summary["max_depth"] == 2
    assert summary["loop_count"] == 2
    assert summary["hotspots"] == []  # no mapped line is inside a loop


def test_analyze_loops_out_of_range_indices_skipped():
    # Stray asm indices (0, beyond the stream) must not raise or miscount.
    line_map = _line_map({1: [0, 4, 999]})
    analyze_loops(line_map, _SINGLE_LOOP)
    assert line_map[1]["loop_depth"] == 1  # only the valid index (4) counts


def test_analyze_loops_does_not_disturb_existing_fields():
    # Regression: the pass only adds loop_depth, leaving prior annotations intact.
    line_map = {1: {"c_lines": [1], "asm_lines": [4], "color": "#000",
                    "branches": [{"mnemonic": "jle"}]}}
    analyze_loops(line_map, _SINGLE_LOOP)
    assert line_map[1]["branches"] == [{"mnemonic": "jle"}]
    assert line_map[1]["loop_depth"] == 1


def test_analyze_loops_empty_line_map():
    summary = analyze_loops({}, _SINGLE_LOOP)
    # No mapped lines, but the back-edge is still counted from the asm.
    assert summary == {"loop_count": 1, "max_depth": 1, "hotspots": []}


# ─── End-to-end: /compile carries the loop summary + matches real asm ────────

@needs_gcc
async def test_compile_response_includes_loop_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\nprint(y)\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["loop_summary"] is not None
    # Straight-line code: no loops anywhere.
    assert body["loop_summary"]["loop_count"] == 0
    assert body["loop_summary"]["max_depth"] == 0
    assert body["loop_summary"]["hotspots"] == []
    # Every mapped line exposes a loop_depth int (0 here).
    for mapping in body["line_map"].values():
        assert "loop_depth" in mapping
        assert isinstance(mapping["loop_depth"], int)
        assert mapping["loop_depth"] == 0


@needs_gcc
async def test_compile_single_loop_has_depth_one(client):
    code = "total = 0\nfor i in range(5):\n    total = total + i\nprint(total)\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()

    summary = body["loop_summary"]
    assert summary["loop_count"] == 1
    assert summary["max_depth"] == 1
    # The loop body line runs inside one loop.
    assert body["line_map"]["3"]["loop_depth"] == 1
    assert {"py_line": 3, "loop_depth": 1} in summary["hotspots"]
    # Ground it in the branch-flow map: a loop IS a backward branch, so the two
    # passes must agree that control flow loops back at least once.
    assert body["branch_summary"]["backward"] >= 1


@needs_gcc
async def test_compile_nested_loops_reach_depth_two(client):
    code = (
        "total = 0\n"
        "for i in range(3):\n"
        "    for j in range(3):\n"
        "        total = total + 1\n"
        "print(total)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()

    summary = body["loop_summary"]
    assert summary["loop_count"] == 2
    assert summary["max_depth"] == 2
    # The innermost body line runs inside both loops.
    assert body["line_map"]["4"]["loop_depth"] == 2
    # The outer-loop header is one level shallower than the inner body.
    assert body["line_map"]["2"]["loop_depth"] == 1
    # Hotspots are ranked deepest-first.
    assert summary["hotspots"][0]["loop_depth"] == 2


@needs_gcc
async def test_compile_while_with_or_condition_is_one_depth_one_loop(client):
    # End-to-end regression for the multi-back-edge bug: a `while` with a
    # compound `or` emits two backward branches to the same body label, but it
    # is one non-nested loop. loop_count must be 1 and max_depth 1, not 2.
    code = (
        "a = 0\n"
        "b = 0\n"
        "t = 0\n"
        "while a < 5 or b < 3:\n"
        "    t = t + 1\n"
        "    a = a + 1\n"
        "    b = b + 1\n"
        "print(t)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    summary = body["loop_summary"]
    assert summary["loop_count"] == 1
    assert summary["max_depth"] == 1
    # The loop body runs inside exactly one loop.
    assert body["line_map"]["5"]["loop_depth"] == 1
    # Sanity: the `or` really did emit more than one backward branch, so this
    # test would fail without the dedup (it is not vacuously passing).
    assert body["branch_summary"]["backward"] >= 2


@needs_gcc
async def test_compile_loop_depth_matches_a_costly_line(client):
    # Pillar-2 payoff: a real idiv buried in a loop. The cost pass flags the
    # divide; the loop map shows it runs every iteration — together they name
    # the true hotspot.
    code = (
        "acc = 0\n"
        "for i in range(10):\n"
        "    acc = acc // i\n"
        "print(acc)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    body = r.json()
    line3 = body["line_map"]["3"]
    assert line3["loop_depth"] == 1          # the divide runs every iteration
    assert "div" in line3["flags"]           # and it is a genuine, costly idiv
