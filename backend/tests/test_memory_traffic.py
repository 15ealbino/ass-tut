"""
Tests for the memory-traffic feature (feat/asm-memory-traffic).

Where the instruction mix lumps every data-movement instruction into a single
"mem" bucket, memory traffic splits that bucket by *direction*: how many memory
reads (loads) and writes (stores) each Python line performs. The lesson is the
read-modify-write round-trip that gcc -O0 forces on every stack-resident
variable — `x += 1` is a load, a compute, and a store just to bump a counter.

Two layers, mirroring test_register_footprint.py / test_instruction_mix.py:
  * Pure-function unit tests for `memory_accesses` / `analyze_memory_traffic` —
    no gcc.
  * End-to-end `/compile` tests that exercise the real transpiler + gcc pipeline
    and assert the load/store signal reaches the API response.

The e2e tests are skipped automatically if gcc (with -m32 support) is missing,
so the suite still passes in a toolchain-less environment.
"""
import shutil
import subprocess

import pytest

from app.compile import (
    analyze_cost,
    analyze_memory_traffic,
    memory_accesses,
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


# ─── Unit: memory_accesses (pure, no gcc) ────────────────────────────────────

@pytest.mark.parametrize(
    "text,expected",
    [
        # ── the canonical read-modify-write round-trip ──
        ("movl -4(%ebp), %eax", (1, 0)),   # load  from a stack slot
        ("addl $1, %eax", (0, 0)),         # compute in a register — no memory
        ("movl %eax, -4(%ebp)", (0, 1)),   # store to a stack slot
        # immediate stored straight to memory is still a store, not a load
        ("movl $5, -4(%ebp)", (0, 1)),
        # arithmetic reading a memory source (register destination) is one load
        ("addl -8(%ebp), %eax", (1, 0)),
        ("imull -8(%ebp), %eax", (1, 0)),
        # ── read-modify-write to a memory destination: load AND store ──
        ("addl %eax, -4(%ebp)", (1, 1)),
        ("incl -4(%ebp)", (1, 1)),         # single-operand RMW
        ("decl -4(%ebp)", (1, 1)),
        ("negl -4(%ebp)", (1, 1)),
        ("shll $2, -4(%ebp)", (1, 1)),     # two-operand shift-to-memory is RMW
        # ── single-operand reads vs writes ──
        ("pushl -4(%ebp)", (1, 0)),        # push reads its operand
        ("popl -4(%ebp)", (0, 1)),         # pop writes its operand
        ("idivl -8(%ebp)", (1, 0)),        # divide by a memory value: read
        # ── compare/test only READ their destination (flags-only) ──
        ("cmpl $0, -4(%ebp)", (1, 0)),
        ("cmpl -4(%ebp), %eax", (1, 0)),
        ("testl %eax, -4(%ebp)", (1, 0)),
        # ── lea is address arithmetic, never a memory access ──
        ("leal -4(%ebp), %eax", (0, 0)),
        ("leal (%eax,%ecx,4), %edx", (0, 0)),
        # ── x87: fld* loads, fst*/fist* store ──
        ("fldl -8(%ebp)", (1, 0)),
        ("fstpl -8(%ebp)", (0, 1)),
        ("fistpl -8(%ebp)", (0, 1)),
        # ── register-only and non-instruction lines contribute nothing ──
        ("movl %eax, %ebx", (0, 0)),
        ("ret", (0, 0)),
        ("pushl %ebp", (0, 0)),            # pushing a register is not data memory
        (".L2:", (0, 0)),
        (".cfi_def_cfa 5, 8", (0, 0)),
        ("", (0, 0)),
        ("   ", (0, 0)),
    ],
)
def test_memory_accesses(text, expected):
    assert memory_accesses(text) == expected


def test_memory_accesses_indexed_source_is_one_load():
    # A comma inside the addressing mode must not be mistaken for an operand
    # separator: `(%eax,%ecx,4)` is a single memory source.
    assert memory_accesses("movl (%eax,%ecx,4), %edx") == (1, 0)


def test_memory_accesses_indexed_destination_store():
    assert memory_accesses("movl %edx, (%eax,%ecx,4)") == (0, 1)


# ─── Unit: analyze_memory_traffic (pure, no gcc) ─────────────────────────────

def test_analyze_memory_traffic_round_trip():
    # The textbook `x += 1` lowering: load, compute, store. One load, one store.
    asm_lines = [
        "movl -4(%ebp), %eax",   # load
        "addl $1, %eax",         # compute
        "movl %eax, -4(%ebp)",   # store
    ]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2, 3], "color": "#000"}}
    summary = analyze_memory_traffic(line_map, asm_lines)

    assert line_map[1]["memory_counts"] == {"loads": 1, "stores": 1}
    assert summary["memory_totals"] == {"loads": 1, "stores": 1}


def test_analyze_memory_traffic_zero_entries_omitted_per_line():
    # A register-only line reports an empty per-line map (mirrors the mix's
    # zero-omission), while the program totals always carry both keys.
    asm_lines = ["movl %eax, %ebx"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1], "color": "#000"}}
    summary = analyze_memory_traffic(line_map, asm_lines)

    assert line_map[1]["memory_counts"] == {}
    assert summary["memory_totals"] == {"loads": 0, "stores": 0}


def test_analyze_memory_traffic_load_only_and_store_only_lines():
    asm_lines = [
        "movl -4(%ebp), %eax",   # line 1: pure load
        "movl %eax, -8(%ebp)",   # line 2: pure store
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [2], "color": "#111"},
    }
    summary = analyze_memory_traffic(line_map, asm_lines)

    assert line_map[1]["memory_counts"] == {"loads": 1}
    assert line_map[2]["memory_counts"] == {"stores": 1}
    assert summary["memory_totals"] == {"loads": 1, "stores": 1}


def test_analyze_memory_traffic_totals_sum_across_lines():
    asm_lines = [
        "movl -4(%ebp), %eax",   # load
        "movl %eax, -8(%ebp)",   # store
        "addl -12(%ebp), %eax",  # load
        "incl -4(%ebp)",         # load + store (RMW)
    ]
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"},
        2: {"c_lines": [2], "asm_lines": [3, 4], "color": "#111"},
    }
    summary = analyze_memory_traffic(line_map, asm_lines)

    assert line_map[1]["memory_counts"] == {"loads": 1, "stores": 1}
    assert line_map[2]["memory_counts"] == {"loads": 2, "stores": 1}
    # 3 loads (1+2), 2 stores (1+1) program-wide.
    assert summary["memory_totals"] == {"loads": 3, "stores": 2}


def test_analyze_memory_traffic_ignores_out_of_range_asm_lines():
    # Defensive: a stray asm index past the end is skipped, mirroring analyze_cost.
    asm_lines = ["movl -4(%ebp), %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 99], "color": "#000"}}
    summary = analyze_memory_traffic(line_map, asm_lines)
    assert line_map[1]["memory_counts"] == {"loads": 1}
    assert summary["memory_totals"] == {"loads": 1, "stores": 0}


def test_analyze_memory_traffic_empty_line_map():
    summary = analyze_memory_traffic({}, [])
    assert summary["memory_totals"] == {"loads": 0, "stores": 0}


def test_analyze_memory_traffic_does_not_disturb_cost_fields():
    # Regression: running the memory pass after analyze_cost leaves the existing
    # cost/mix annotations intact and merely adds `memory_counts`.
    asm_lines = ["movl -4(%ebp), %eax", "imull %edx, %eax"]
    line_map = {1: {"c_lines": [1], "asm_lines": [1, 2], "color": "#000"}}
    cost = analyze_cost(line_map, asm_lines)
    analyze_memory_traffic(line_map, asm_lines)

    assert line_map[1]["asm_count"] == 2
    assert line_map[1]["flags"] == ["mul"]
    assert line_map[1]["category_counts"] == {"mem": 1, "compute": 1}
    assert cost["total_instructions"] == 2
    # And the new field is present alongside the old ones: one load (the movl),
    # the imul is register-only.
    assert line_map[1]["memory_counts"] == {"loads": 1}


# ─── End-to-end: /compile carries the memory-traffic summary ─────────────────

@needs_gcc
async def test_compile_response_includes_memory_summary(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = x + 2\n"})
    assert r.status_code == 200
    body = r.json()
    assert body["memory_summary"] is not None
    totals = body["memory_summary"]["memory_totals"]
    assert set(totals.keys()) == {"loads", "stores"}
    # Storing results into stack slots means there is real store traffic.
    assert totals["stores"] > 0
    # Every mapped line carries a memory_counts map.
    for mapping in body["line_map"].values():
        assert "memory_counts" in mapping
        assert isinstance(mapping["memory_counts"], dict)


@needs_gcc
async def test_compile_augassign_is_load_and_store(client):
    # `x += 1` on a stack-resident variable is the feature's headline lesson: a
    # read-modify-write round-trip. The program must show BOTH load and store
    # traffic (the increment reloads x and writes it back).
    r = await client.post("/compile", json={"code": "x = 0\nx += 1\n"})
    assert r.status_code == 200
    totals = r.json()["memory_summary"]["memory_totals"]
    assert totals["loads"] > 0
    assert totals["stores"] > 0


@needs_gcc
async def test_compile_memory_counts_bounded_by_instruction_count(client):
    # Invariant: each instruction touches memory at most twice (one load + one
    # store, the read-modify-write case), so a line's loads + stores can never
    # exceed 2× its instruction count.
    r = await client.post("/compile", json={"code": "a = 3\nb = 4\nc = a * b\n"})
    assert r.status_code == 200
    body = r.json()
    for mapping in body["line_map"].values():
        counts = mapping["memory_counts"]
        mem_ops = counts.get("loads", 0) + counts.get("stores", 0)
        # At most two memory touches (one load + one store) per instruction.
        assert mem_ops <= 2 * mapping["asm_count"]
