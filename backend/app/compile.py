"""
Compile endpoint logic: Python → C → x86 Assembly.
All subprocess calls run in a thread-pool to avoid blocking the event loop.
"""
import asyncio
import os
import re
import subprocess
import tempfile
from functools import partial
from typing import Dict, List, Tuple

from app.transpiler import TranspileError, build_line_map, transpile

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
        try:
            result = subprocess.run(
                ["gcc", "-S", "-O0", "-m32", "-o", asm_path, c_path],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
        except FileNotFoundError:
            # gcc not found — try without -m32 (64-bit fallback)
            result = subprocess.run(
                ["gcc", "-S", "-O0", "-o", asm_path, c_path],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
        if result.returncode != 0:
            raise CompileError(f"GCC error:\n{result.stderr}")
        with open(asm_path) as f:
            return f.read()


def _parse_asm_line_map(asm_text: str) -> Dict[int, List[int]]:
    """
    Parse GCC .loc directives to build c_lineno → [asm_lineno] mapping.
    GCC emits:   .loc 1 <c_line> 0
    """
    c_to_asm: Dict[int, List[int]] = {}
    current_c_line: int | None = None
    asm_lines = asm_text.splitlines()
    for asm_lineno, line in enumerate(asm_lines, start=1):
        stripped = line.strip()
        m = re.match(r'\.loc\s+\d+\s+(\d+)', stripped)
        if m:
            current_c_line = int(m.group(1))
        elif current_c_line is not None and not stripped.startswith('.') and stripped:
            c_to_asm.setdefault(current_c_line, []).append(asm_lineno)
    return c_to_asm


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

    loop = asyncio.get_event_loop()
    try:
        asm_text = await asyncio.wait_for(
            loop.run_in_executor(None, partial(_run_gcc, c_source)),
            timeout=TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        raise CompileError("Compilation timed out")
    except CompileError:
        raise
    except Exception as e:
        raise CompileError(f"Compilation failed: {e}")

    c_to_asm = _parse_asm_line_map(asm_text)
    line_map = build_line_map(lines, py_to_c, c_to_asm)

    return {
        "python_lines": lines,
        "c_code": c_source,
        "c_lines": c_source.splitlines(),
        "asm_code": asm_text,
        "asm_lines": asm_text.splitlines(),
        "line_map": line_map,
    }
