"""
Alternative compile path: Python → native binary (Nuitka) → Ghidra (via
PyGhidra) → disassembly + decompiled C.

This is the "second backend" exposed alongside the AST-to-C transpiler. It is
heavyweight: each call spawns Nuitka (which itself runs gcc), then spins up
a Ghidra headless project against the produced binary, runs auto-analysis,
and extracts:

  * the disassembly of `main` (or, if not found, the largest user function)
  * Ghidra's decompiled C for the same function

Both are returned in the same shape as the transpile path so the frontend
panes do not need to special-case anything. `line_map` is returned empty:
there is no reliable mapping from a Python source line through Nuitka's
synthesized CPython glue down to a specific machine-code address.

Dependencies (not installed by default):
  * `nuitka`           (pip install nuitka)
  * `pyghidra`         (pip install pyghidra)
  * Ghidra + JDK, with `GHIDRA_INSTALL_DIR` pointing at the install root

If any of these are missing the endpoint raises `PyGhidraUnavailable`, which
the API surfaces as HTTP 503 with a clear message. Nothing about this module
crashes the server on import — every check is deferred to call time.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from functools import partial
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

# Generous timeouts: Nuitka itself runs gcc and may take 20–40 s on a cold
# cache; Ghidra auto-analysis on a small binary takes another 10–30 s.
NUITKA_TIMEOUT = 120  # seconds
GHIDRA_TIMEOUT = 180  # seconds
MAX_LINES = 200
MAX_CHARS = 10_000


class PyGhidraUnavailable(Exception):
    """Raised when Nuitka, pyghidra, or a configured Ghidra install is missing.

    The /compile endpoint converts this into a 503 with the underlying detail
    rather than the generic 422 used for transpile errors.
    """


class PyGhidraCompileError(Exception):
    """Raised on any failure during the Nuitka or Ghidra steps themselves."""


# ── Availability probes ─────────────────────────────────────────────────────


def check_available() -> None:
    """Raise PyGhidraUnavailable with a precise reason if anything's missing.

    Called at request time, not import time, so a backend without the heavy
    toolchain still starts cleanly and only returns 503 if a user actually
    picks the pyghidra method.
    """
    # 1. Nuitka — invoked as `python -m nuitka`
    try:
        result = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            raise PyGhidraUnavailable(
                f"`python -m nuitka --version` exited {result.returncode}: "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
    except FileNotFoundError:
        raise PyGhidraUnavailable("Nuitka not installed (pip install nuitka)")
    except subprocess.TimeoutExpired:
        raise PyGhidraUnavailable("Nuitka version probe timed out")

    # 2. pyghidra — Python package wrapping the Ghidra JVM
    try:
        import pyghidra  # noqa: F401
    except ImportError as e:
        raise PyGhidraUnavailable(f"pyghidra not installed (pip install pyghidra): {e}")

    # 3. GHIDRA_INSTALL_DIR — pyghidra cannot find Ghidra without this
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install_dir:
        raise PyGhidraUnavailable(
            "GHIDRA_INSTALL_DIR is not set. Download Ghidra and export "
            "GHIDRA_INSTALL_DIR=/path/to/ghidra_X.Y.Z_PUBLIC"
        )
    if not Path(install_dir).is_dir():
        raise PyGhidraUnavailable(f"GHIDRA_INSTALL_DIR ({install_dir}) is not a directory")


# ── Nuitka step ─────────────────────────────────────────────────────────────


def _run_nuitka(python_source: str, work_dir: Path) -> Path:
    """Compile the Python source to a standalone native binary.

    Uses Nuitka's default (non-onefile, non-standalone) mode which still
    produces a working ELF that imports libpython at runtime. That binary is
    enough for Ghidra to disassemble the user's main() — we don't need the
    binary to run anywhere.
    """
    py_path = work_dir / "user_script.py"
    py_path.write_text(python_source)

    bin_path = work_dir / "user_script.bin"
    cmd = [
        sys.executable, "-m", "nuitka",
        "--no-pyi-file",
        "--remove-output",
        f"--output-dir={work_dir}",
        f"--output-filename={bin_path.name}",
        str(py_path),
    ]
    logger.info("Running Nuitka: %s", " ".join(cmd))
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=NUITKA_TIMEOUT,
    )
    if result.returncode != 0:
        # Nuitka tends to write the actual error to stderr; surface its tail
        # so we don't bury the cause in C-compile noise.
        tail = "\n".join(result.stderr.splitlines()[-12:])
        raise PyGhidraCompileError(f"Nuitka failed (exit {result.returncode}):\n{tail}")
    if not bin_path.exists():
        raise PyGhidraCompileError(
            f"Nuitka reported success but produced no binary at {bin_path}"
        )
    return bin_path


# ── Ghidra step ─────────────────────────────────────────────────────────────


def _analyze_with_ghidra(binary_path: Path) -> tuple[str, str]:
    """Run Ghidra against the binary; return (asm_text, decompiled_c_text).

    Imports pyghidra lazily so a missing install only bites callers, not
    everyone who imports this module.
    """
    import pyghidra  # noqa: WPS433  (re-import inside function is intentional)

    if not pyghidra.started():
        pyghidra.start()

    # Ghidra Python API objects — imported only after pyghidra.start() has
    # initialized the JVM and made the `ghidra.*` packages importable.
    from ghidra.app.decompiler import DecompInterface  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

    asm_lines: List[str] = []
    c_text = ""

    with pyghidra.open_program(str(binary_path), analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        listing = program.getListing()

        # Pick the target function. We prefer `main`; if Nuitka renamed it (it
        # often does — entry-point glue lives elsewhere), fall back to the
        # largest function by instruction count, which tends to be the user's
        # transpiled module body.
        target = None
        fn_iter = listing.getFunctions(True)
        functions = list(fn_iter)
        for fn in functions:
            if fn.getName() == "main":
                target = fn
                break
        if target is None and functions:
            target = max(functions, key=lambda f: f.getBody().getNumAddresses())
        if target is None:
            raise PyGhidraCompileError("Ghidra found no functions in the binary")

        # Disassembly listing of the chosen function
        body = target.getBody()
        instr_iter = listing.getInstructions(body, True)
        for instr in instr_iter:
            asm_lines.append(f"{instr.getAddressString(False, True)}: {instr}")

        # Decompiled C of the same function
        decompiler = DecompInterface()
        try:
            decompiler.openProgram(program)
            monitor = ConsoleTaskMonitor()
            result = decompiler.decompileFunction(target, 60, monitor)
            if result.decompileCompleted():
                c_text = result.getDecompiledFunction().getC()
            else:
                c_text = f"// Ghidra decompiler failed: {result.getErrorMessage()}"
        finally:
            decompiler.dispose()

    return ("\n".join(asm_lines), c_text)


# ── Public entry ────────────────────────────────────────────────────────────


def _compile_sync(python_source: str) -> dict:
    """Synchronous worker; the async wrapper runs this in an executor."""
    check_available()
    with tempfile.TemporaryDirectory(prefix="pyghidra_compile_") as tmp:
        work = Path(tmp)
        binary = _run_nuitka(python_source, work)
        asm_text, c_text = _analyze_with_ghidra(binary)
    return {"asm": asm_text, "c": c_text}


async def compile_pyghidra(python_source: str) -> dict:
    """Async entry point — same return shape as compile.compile_python().

    Raises PyGhidraUnavailable (→ 503) if the toolchain is not installed,
    or PyGhidraCompileError (→ 422) on any Nuitka / Ghidra failure.
    """
    lines = python_source.splitlines()
    if len(lines) > MAX_LINES:
        raise PyGhidraCompileError(f"Input too long: max {MAX_LINES} lines")
    if len(python_source) > MAX_CHARS:
        raise PyGhidraCompileError(f"Input too long: max {MAX_CHARS} characters")

    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, partial(_compile_sync, python_source)),
            timeout=NUITKA_TIMEOUT + GHIDRA_TIMEOUT + 10,
        )
    except asyncio.TimeoutError:
        logger.error("PyGhidra pipeline timed out")
        raise PyGhidraCompileError("PyGhidra pipeline timed out")

    c_lines = result["c"].splitlines()
    asm_lines = result["asm"].splitlines()
    return {
        "python_lines": lines,
        "c_code": result["c"],
        "c_lines": c_lines,
        "asm_code": result["asm"],
        "asm_lines": asm_lines,
        # No line-level mapping: Nuitka's CPython glue makes line-accurate
        # tracing from Python lineno → machine address infeasible without a
        # custom DWARF-emitter on top of Nuitka.
        "line_map": {},
    }
