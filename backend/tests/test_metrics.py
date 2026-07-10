"""
Tests for the assembly cost-lens metrics (backend/app/metrics.py) plus the
`asm_count` / `c_count` fields build_line_map now attaches, and the end-to-end
`metrics` block on the /compile transpile response.

The pure-metrics tests need no gcc. The e2e tests are guarded by `requires_gcc`
so environments without 32-bit multilib skip them cleanly rather than fail.
"""
import shutil
import subprocess

import pytest

from app.metrics import HOTSPOT_THRESHOLD, build_expansion_metrics
from app.transpiler import build_line_map


def _gcc_m32_works() -> bool:
    """True only if `gcc -m32` can compile a stdio program — the transpiler
    always emits `#include <stdio.h>`, which needs the 32-bit libc headers."""
    if shutil.which("gcc") is None:
        return False
    try:
        proc = subprocess.run(
            ["gcc", "-m32", "-S", "-x", "c", "-", "-o", "/dev/null"],
            input="#include <stdio.h>\nint main(){return 0;}\n",
            capture_output=True,
            text=True,
            timeout=15,
        )
        return proc.returncode == 0
    except Exception:
        return False


requires_gcc = pytest.mark.skipif(
    not _gcc_m32_works(),
    reason="gcc -m32 with 32-bit libc headers not available in this environment",
)


# ─── build_expansion_metrics (pure) ──────────────────────────────────────────


def test_metrics_empty_line_map():
    m = build_expansion_metrics({})
    assert m["total_asm_instructions"] == 0
    assert m["total_c_lines"] == 0
    assert m["line_count"] == 0
    assert m["mean_asm_per_line"] == 0.0
    assert m["max_asm_line"] is None
    assert m["hotspots"] == []
    assert m["hotspot_threshold"] == HOTSPOT_THRESHOLD
    assert m["per_line"] == {}


def test_metrics_counts_and_mean():
    line_map = {
        1: {"c_lines": [1], "asm_lines": [1, 2]},
        2: {"c_lines": [2, 3], "asm_lines": [3, 4, 5, 6]},
    }
    m = build_expansion_metrics(line_map)
    assert m["total_asm_instructions"] == 6      # 2 + 4
    assert m["total_c_lines"] == 3               # 1 + 2
    assert m["line_count"] == 2
    assert m["mean_asm_per_line"] == 3.0         # 6 / 2
    assert m["per_line"] == {
        1: {"c_count": 1, "asm_count": 2},
        2: {"c_count": 2, "asm_count": 4},
    }


def test_metrics_max_asm_line_ties_break_to_lowest_pyline():
    # Two lines with equal asm expansion → the lower py_lineno wins.
    line_map = {
        5: {"c_lines": [1], "asm_lines": [1, 2, 3]},
        2: {"c_lines": [2], "asm_lines": [4, 5, 6]},
    }
    m = build_expansion_metrics(line_map)
    assert m["max_asm_line"] == 2


def test_metrics_max_asm_line_none_when_no_instructions():
    # Lines mapped only to non-instruction C (empty asm) → no max.
    line_map = {
        1: {"c_lines": [1], "asm_lines": []},
        2: {"c_lines": [2], "asm_lines": []},
    }
    m = build_expansion_metrics(line_map)
    assert m["max_asm_line"] is None
    assert m["total_asm_instructions"] == 0


def test_metrics_hotspot_threshold_is_inclusive():
    # Exactly at the threshold counts as a hotspot; one below does not.
    at = list(range(1, HOTSPOT_THRESHOLD + 1))          # len == threshold
    below = list(range(1, HOTSPOT_THRESHOLD))           # len == threshold - 1
    line_map = {
        1: {"c_lines": [1], "asm_lines": at},
        2: {"c_lines": [2], "asm_lines": below},
    }
    m = build_expansion_metrics(line_map)
    assert m["hotspots"] == [1]


def test_metrics_hotspots_sorted():
    big = list(range(HOTSPOT_THRESHOLD + 5))
    line_map = {
        7: {"c_lines": [1], "asm_lines": big},
        3: {"c_lines": [2], "asm_lines": big},
        1: {"c_lines": [3], "asm_lines": [1]},
    }
    m = build_expansion_metrics(line_map)
    assert m["hotspots"] == [3, 7]


def test_metrics_tolerates_entries_without_asm_lines_key():
    # build_expansion_metrics reads counts defensively via .get.
    m = build_expansion_metrics({1: {"color": "#fff"}})
    assert m["per_line"] == {1: {"c_count": 0, "asm_count": 0}}
    assert m["total_asm_instructions"] == 0


# ─── build_line_map now carries per-line counts ──────────────────────────────


def test_build_line_map_attaches_counts():
    py_to_c = {1: [1], 2: [2, 3]}
    c_to_asm = {1: [10, 11], 2: [20], 3: [21, 22, 23]}
    line_map = build_line_map(["x = 1", "y = 2"], py_to_c, c_to_asm)

    assert line_map[1]["asm_count"] == len(line_map[1]["asm_lines"]) == 2
    assert line_map[1]["c_count"] == len(line_map[1]["c_lines"]) == 1
    # py line 2 → c lines 2,3 → asm 20,21,22,23
    assert line_map[2]["c_count"] == 2
    assert line_map[2]["asm_count"] == 4
    # Existing keys are preserved.
    assert set(line_map[1]) >= {"c_lines", "asm_lines", "color"}


def test_build_line_map_and_metrics_agree():
    py_to_c = {1: [1], 2: [2, 3]}
    c_to_asm = {1: [10, 11], 2: [20], 3: [21, 22, 23]}
    line_map = build_line_map(["a", "b"], py_to_c, c_to_asm)
    m = build_expansion_metrics(line_map)
    # The summary totals must match the per-entry counts on the map.
    assert m["total_asm_instructions"] == sum(
        e["asm_count"] for e in line_map.values()
    )
    assert m["total_c_lines"] == sum(e["c_count"] for e in line_map.values())


# ─── end-to-end via /compile (requires gcc -m32) ─────────────────────────────

pytestmark_e2e = pytest.mark.asyncio


@requires_gcc
@pytest.mark.asyncio
async def test_compile_response_includes_metrics(client):
    r = await client.post("/compile", json={"code": "x = 42\ny = x + 1\n"})
    assert r.status_code == 200
    metrics = r.json()["metrics"]
    assert metrics is not None
    assert metrics["total_asm_instructions"] > 0
    assert metrics["hotspot_threshold"] == HOTSPOT_THRESHOLD
    # Summary total must equal the sum of per-line asm counts (JSON keys are str).
    per_line_sum = sum(v["asm_count"] for v in metrics["per_line"].values())
    assert per_line_sum == metrics["total_asm_instructions"]


@requires_gcc
@pytest.mark.asyncio
async def test_compile_line_map_has_asm_count(client):
    r = await client.post("/compile", json={"code": "x = 42\n"})
    assert r.status_code == 200
    mapping = r.json()["line_map"]["1"]
    assert "asm_count" in mapping and "c_count" in mapping
    assert mapping["asm_count"] == len(mapping["asm_lines"])


@requires_gcc
@pytest.mark.asyncio
async def test_compile_flags_hotspot_line(client):
    # Heavy arithmetic on line 3 and a multi-arg print on line 4 each expand
    # well past the 10-instruction threshold, so both are flagged.
    code = (
        "a = 5\n"
        "b = 7\n"
        "c = ((a * b) + (a * a) + (b * b)) * ((a + b) * (a - b))\n"
        "print(a, b, c, a + b, a * b)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200
    metrics = r.json()["metrics"]
    assert 3 in metrics["hotspots"]
    assert 4 in metrics["hotspots"]
    # The busiest line is one of the two hotspots.
    assert metrics["max_asm_line"] in (3, 4)


@pytest.mark.asyncio
async def test_compile_pyghidra_metrics_is_null(client):
    # The pyghidra backend returns no line map, so metrics must serialize as
    # null rather than crashing the response model.
    from unittest.mock import AsyncMock, patch

    fake = {
        "python_lines": ["x = 1"],
        "c_code": "undefined4 main(void) {}",
        "c_lines": ["undefined4 main(void) {}"],
        "asm_code": "00401000: ENDBR64",
        "asm_lines": ["00401000: ENDBR64"],
        "line_map": {},
    }
    with patch("app.main.compile_pyghidra", new=AsyncMock(return_value=fake)):
        r = await client.post(
            "/compile", json={"code": "x = 1", "method": "pyghidra"}
        )
    assert r.status_code == 200
    assert r.json()["metrics"] is None
