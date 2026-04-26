"""
Compile endpoint logic: Python → C → x86 Assembly.
All subprocess calls run in a thread-pool to avoid blocking the event loop.
"""
import asyncio
import logging
import os
import re
import subprocess
import tempfile
from functools import partial
from typing import Dict, List, Tuple

from app.transpiler import TranspileError, build_line_map, transpile

logger = logging.getLogger(__name__)

MAX_LINES = 200
MAX_CHARS = 10_000
TIMEOUT = 10  # seconds


class CompileError(Exception):
    pass


def _run_gcc(c_source: str) -> str:
    """Compile C source to x86 assembly, return asm text. Runs synchronously."""
    with tempfile.TemporaryDirectory() as tmp:
        c_path = os.path.join(tmp, "code.c")
        asm_path = os.path.join(tmp, "code.s")
        with open(c_path, "w") as f:
            f.write(c_source)
        result = subprocess.run(
            ["gcc", "-S", "-O0", "-m32", "-g1", "-o", asm_path, c_path],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        if result.returncode != 0:
            stderr_clean = result.stderr.replace(c_path, "input.c")
            raise CompileError(f"GCC error:\n{stderr_clean}")
        with open(asm_path) as f:
            return f.read()


def _parse_asm_line_map(asm_text: str) -> Tuple[Dict[int, List[int]], str]:
    """
    Parse GCC .loc directives to build c_lineno → [display_asm_lineno] mapping.
    Strips .loc and .file directives plus .debug_* sections from the returned
    display text so the frontend never sees them.
    """
    c_to_asm: Dict[int, List[int]] = {}
    current_c_line: int | None = None
    display_lines: List[str] = []
    in_debug_section = False

    for line in asm_text.splitlines():
        stripped = line.strip()

        # Enter / stay in a .debug_* section — skip everything in it
        if re.match(r'\.section\s+\.debug', stripped):
            in_debug_section = True
        if in_debug_section:
            # Leave when we hit a new .section that isn't .debug_*
            if re.match(r'\.section\b', stripped) and not re.match(r'\.section\s+\.debug', stripped):
                in_debug_section = False
            else:
                continue

        # .file directives are debug-only noise
        if stripped.startswith('.file'):
            continue

        # Parse .loc but don't emit it to the display
        m = re.match(r'\.loc\s+\d+\s+(\d+)', stripped)
        if m:
            current_c_line = int(m.group(1))
            continue

        display_lines.append(line)
        display_lineno = len(display_lines)  # 1-indexed in the filtered output

        is_instruction = (
            current_c_line is not None
            and stripped
            and not stripped.startswith('.')
            and not stripped.endswith(':')
        )
        if is_instruction:
            c_to_asm.setdefault(current_c_line, []).append(display_lineno)

    return c_to_asm, '\n'.join(display_lines)


async def compile_python(python_source: str) -> dict:
    lines = python_source.splitlines()
    if len(lines) > MAX_LINES:
        raise CompileError(f"Input too long: max {MAX_LINES} lines")
    if len(python_source) > MAX_CHARS:
        raise CompileError(f"Input too long: max {MAX_CHARS} characters")

    try:
        c_source, py_to_c = transpile(python_source)
    except TranspileError as e:
        raise CompileError(str(e))

    loop = asyncio.get_running_loop()
    try:
        asm_text = await asyncio.wait_for(
            loop.run_in_executor(None, partial(_run_gcc, c_source)),
            timeout=TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        logger.error("GCC timed out after %ds", TIMEOUT)
        raise CompileError("Compilation timed out")
    except CompileError:
        raise
    except Exception as e:
        logger.exception("Unexpected compilation failure")
        raise CompileError(f"Compilation failed: {e}")

    c_to_asm, filtered_asm = _parse_asm_line_map(asm_text)
    line_map = build_line_map(lines, py_to_c, c_to_asm)

    return {
        "python_lines": lines,
        "c_code": c_source,
        "c_lines": c_source.splitlines(),
        "asm_code": filtered_asm,
        "asm_lines": filtered_asm.splitlines(),
        "line_map": line_map,
    }
