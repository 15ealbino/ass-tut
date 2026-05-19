"""
Unit tests for app.pyghidra_compile — internal error paths.

The API-level tests in test_compile.py mock compile_pyghidra() as a whole,
so the internal functions are untested at unit level:

  - check_available()       — 6 distinct failure paths + happy path
  - _run_nuitka()           — non-zero exit, missing binary, stderr tail
  - _analyze_with_ghidra()  — no functions found in the binary
  - compile_pyghidra()      — input-size guards, asyncio timeout

pyghidra and Ghidra are not expected in the test environment; every path
that would import or invoke them is mocked with unittest.mock.
"""

import asyncio
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.pyghidra_compile import (
    MAX_CHARS,
    MAX_LINES,
    PyGhidraCompileError,
    PyGhidraUnavailable,
    _analyze_with_ghidra,
    _run_nuitka,
    check_available,
    compile_pyghidra,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _nuitka_ok() -> subprocess.CompletedProcess:
    """Fake `python -m nuitka --version` that exits cleanly."""
    return subprocess.CompletedProcess(
        args=[], returncode=0, stdout="Nuitka 1.9.0", stderr=""
    )


# ═══════════════════════════════════════════════════════════════════════════════
# check_available() — six failure paths + one success path
# ═══════════════════════════════════════════════════════════════════════════════


def test_check_available_raises_when_nuitka_not_found():
    """FileNotFoundError from subprocess means Nuitka is not installed."""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        with pytest.raises(PyGhidraUnavailable) as ei:
            check_available()
    msg = str(ei.value)
    assert "nuitka" in msg.lower()
    assert "pip install" in msg


def test_check_available_raises_when_nuitka_exits_nonzero():
    """A non-zero Nuitka exit-code surfaces the code in the error message."""
    bad = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="fatal: no C compiler"
    )
    with patch("subprocess.run", return_value=bad):
        with pytest.raises(PyGhidraUnavailable) as ei:
            check_available()
    assert "exited 1" in str(ei.value)


def test_check_available_raises_when_nuitka_times_out():
    """`TimeoutExpired` from the version probe → 'timed out' message."""
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="nuitka", timeout=15),
    ):
        with pytest.raises(PyGhidraUnavailable) as ei:
            check_available()
    assert "timed out" in str(ei.value).lower()


def test_check_available_raises_when_pyghidra_not_installed():
    """Nuitka OK but `import pyghidra` fails → PyGhidraUnavailable."""
    with patch("subprocess.run", return_value=_nuitka_ok()):
        # Setting sys.modules entry to None makes any subsequent import of
        # that name raise ImportError in Python 3.
        with patch.dict(sys.modules, {"pyghidra": None}):
            with pytest.raises(PyGhidraUnavailable) as ei:
                check_available()
    assert "pyghidra not installed" in str(ei.value).lower()


def test_check_available_raises_when_ghidra_install_dir_not_set(monkeypatch):
    """Nuitka + pyghidra both available but GHIDRA_INSTALL_DIR is absent."""
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    with patch("subprocess.run", return_value=_nuitka_ok()):
        with patch.dict(sys.modules, {"pyghidra": MagicMock()}):
            with pytest.raises(PyGhidraUnavailable) as ei:
                check_available()
    msg = str(ei.value)
    assert "GHIDRA_INSTALL_DIR" in msg
    assert "not set" in msg.lower()


def test_check_available_raises_when_ghidra_install_dir_not_a_directory(
    monkeypatch, tmp_path
):
    """GHIDRA_INSTALL_DIR set to a path that doesn't exist as a directory."""
    nonexistent = str(tmp_path / "no_such_ghidra_here")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", nonexistent)
    with patch("subprocess.run", return_value=_nuitka_ok()):
        with patch.dict(sys.modules, {"pyghidra": MagicMock()}):
            with pytest.raises(PyGhidraUnavailable) as ei:
                check_available()
    msg = str(ei.value)
    assert "not a directory" in msg.lower()
    assert nonexistent in msg


def test_check_available_passes_when_all_deps_present(monkeypatch, tmp_path):
    """No exception when Nuitka, pyghidra, and a valid GHIDRA_INSTALL_DIR are all OK."""
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
    with patch("subprocess.run", return_value=_nuitka_ok()):
        with patch.dict(sys.modules, {"pyghidra": MagicMock()}):
            check_available()  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# _run_nuitka() — failure paths
# ═══════════════════════════════════════════════════════════════════════════════


def test_run_nuitka_raises_on_nonzero_exit(tmp_path):
    """Nuitka exits 1 → PyGhidraCompileError naming exit code."""
    failed = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="",
        stderr="SyntaxError: invalid syntax\n",
    )
    with patch("subprocess.run", return_value=failed):
        with pytest.raises(PyGhidraCompileError) as ei:
            _run_nuitka("x = 1", tmp_path)
    msg = str(ei.value)
    assert "Nuitka failed" in msg
    assert "exit 1" in msg


def test_run_nuitka_raises_when_binary_missing_after_success(tmp_path):
    """Nuitka exits 0 but never writes the binary → PyGhidraCompileError."""
    ok = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with patch("subprocess.run", return_value=ok):
        with pytest.raises(PyGhidraCompileError) as ei:
            _run_nuitka("x = 1", tmp_path)
    assert "produced no binary" in str(ei.value).lower()


def test_run_nuitka_includes_stderr_tail_in_error(tmp_path):
    """The final lines of Nuitka's stderr must appear in the error message
    so the caller can see the actual failure reason without digging through
    logs."""
    noise = "\n".join(f"info: compiling line {i}" for i in range(20))
    last_line = "fatal error: undefined reference to `main'"
    failed = subprocess.CompletedProcess(
        args=[], returncode=2, stdout="",
        stderr=noise + "\n" + last_line,
    )
    with patch("subprocess.run", return_value=failed):
        with pytest.raises(PyGhidraCompileError) as ei:
            _run_nuitka("x = 1", tmp_path)
    assert last_line in str(ei.value)


# ═══════════════════════════════════════════════════════════════════════════════
# _analyze_with_ghidra() — no functions in binary
# ═══════════════════════════════════════════════════════════════════════════════


def test_analyze_with_ghidra_raises_when_no_functions_found(tmp_path):
    """If Ghidra's analysis yields no functions, raise PyGhidraCompileError
    before attempting to disassemble or decompile anything."""
    fake_binary = tmp_path / "stub.bin"
    fake_binary.write_bytes(b"\x00" * 8)  # content irrelevant; never opened for real

    # Listing with an empty function iterator.
    mock_listing = MagicMock()
    mock_listing.getFunctions.return_value = iter([])

    mock_program = MagicMock()
    mock_program.getListing.return_value = mock_listing

    mock_flat_api = MagicMock()
    mock_flat_api.getCurrentProgram.return_value = mock_program

    # open_program is used as a context manager.
    mock_ctx = MagicMock()
    mock_ctx.__enter__ = MagicMock(return_value=mock_flat_api)
    mock_ctx.__exit__ = MagicMock(return_value=False)

    mock_pyghidra = MagicMock()
    mock_pyghidra.started.return_value = True  # skip pyghidra.start()
    mock_pyghidra.open_program.return_value = mock_ctx

    # Stub the Ghidra Java packages imported after pyghidra.start().
    ghidra_stubs = {
        "pyghidra": mock_pyghidra,
        "ghidra": MagicMock(),
        "ghidra.app": MagicMock(),
        "ghidra.app.decompiler": MagicMock(),
        "ghidra.util": MagicMock(),
        "ghidra.util.task": MagicMock(),
    }
    with patch.dict(sys.modules, ghidra_stubs):
        with pytest.raises(PyGhidraCompileError) as ei:
            _analyze_with_ghidra(fake_binary)
    assert "no functions" in str(ei.value).lower()


# ═══════════════════════════════════════════════════════════════════════════════
# compile_pyghidra() — input validation and timeout (no toolchain invoked)
# ═══════════════════════════════════════════════════════════════════════════════


async def test_compile_pyghidra_rejects_source_exceeding_line_limit():
    """Source with more than MAX_LINES lines is rejected before touching subprocess."""
    oversized = "\n".join(f"x{i} = {i}" for i in range(MAX_LINES + 1))
    with pytest.raises(PyGhidraCompileError) as ei:
        await compile_pyghidra(oversized)
    msg = str(ei.value)
    assert "too long" in msg.lower()
    assert str(MAX_LINES) in msg


async def test_compile_pyghidra_rejects_source_exceeding_char_limit():
    """Source with more than MAX_CHARS characters is rejected before touching subprocess."""
    oversized = "x = " + "1" * MAX_CHARS  # exceeds the limit by a few chars
    with pytest.raises(PyGhidraCompileError) as ei:
        await compile_pyghidra(oversized)
    msg = str(ei.value)
    assert "too long" in msg.lower()
    assert str(MAX_CHARS) in msg


async def test_compile_pyghidra_timeout_raises_compile_error():
    """asyncio.TimeoutError from the executor wait is caught and re-raised as
    PyGhidraCompileError so the API surfaces it as a 422 with a clear message
    rather than an unhandled 500."""
    with patch(
        "asyncio.wait_for",
        new=AsyncMock(side_effect=asyncio.TimeoutError),
    ):
        with pytest.raises(PyGhidraCompileError) as ei:
            await compile_pyghidra("x = 1")
    assert "timed out" in str(ei.value).lower()
