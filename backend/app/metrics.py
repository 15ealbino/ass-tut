"""
Assembly-expansion metrics — the "cost lens".

Given the per-Python-line map produced by `build_line_map`, summarize how much
machine code each source line expands into. The goal is educational: a single
innocent-looking Python line can balloon into many x86 instructions, and making
that visible teaches learners to spot bloated / inefficient assembly and reason
about why one line costs more than another.

Everything here is pure (no gcc, no I/O), so it is cheap to unit-test.
"""
from typing import Dict, List

# A Python line whose asm expansion reaches this many instructions is flagged as
# a "hotspot" worth inspecting. Deliberately a fixed, explainable constant rather
# than a statistical cutoff: "any line that compiles to >=10 machine instructions"
# is easy for a learner to reason about.
HOTSPOT_THRESHOLD = 10


def build_expansion_metrics(line_map: Dict[int, dict]) -> dict:
    """Summarize per-line assembly expansion from a `build_line_map` result.

    `line_map` maps py_lineno -> {"c_lines": [...], "asm_lines": [...], ...}.
    Only the *counts* of mapped lines matter here, so this works whether or not
    the entries carry the `c_count` / `asm_count` convenience fields.

    Returns a JSON-serializable summary:
      total_asm_instructions  sum of asm instructions across all mapped lines
      total_c_lines           sum of C lines across all mapped lines
      line_count              number of Python lines that mapped to any output
      mean_asm_per_line       total_asm_instructions / line_count (0.0 if none)
      max_asm_line            py_lineno with the most asm instructions, or None
      hotspots                sorted py_linenos with asm_count >= threshold
      hotspot_threshold       the threshold used (echoed for the UI/legend)
      per_line                py_lineno -> {"c_count", "asm_count"}
    """
    per_line: Dict[int, Dict[str, int]] = {}
    total_asm = 0
    total_c = 0

    for py_line, mapping in line_map.items():
        asm_count = len(mapping.get("asm_lines", []))
        c_count = len(mapping.get("c_lines", []))
        per_line[py_line] = {"c_count": c_count, "asm_count": asm_count}
        total_asm += asm_count
        total_c += c_count

    line_count = len(per_line)
    mean_asm = round(total_asm / line_count, 2) if line_count else 0.0

    hotspots: List[int] = sorted(
        py_line
        for py_line, counts in per_line.items()
        if counts["asm_count"] >= HOTSPOT_THRESHOLD
    )

    # The line with the largest asm expansion; ties break toward the lowest
    # py_lineno so the result is deterministic. None when nothing mapped.
    max_asm_line = None
    if per_line:
        max_asm_line = min(
            per_line,
            key=lambda pl: (-per_line[pl]["asm_count"], pl),
        )
        if per_line[max_asm_line]["asm_count"] == 0:
            max_asm_line = None

    return {
        "total_asm_instructions": total_asm,
        "total_c_lines": total_c,
        "line_count": line_count,
        "mean_asm_per_line": mean_asm,
        "max_asm_line": max_asm_line,
        "hotspots": hotspots,
        "hotspot_threshold": HOTSPOT_THRESHOLD,
        "per_line": per_line,
    }
