"""
Tests for the stdlib import-shim system in the transpiler.

These exercise the (module, attr) shim registry: imports register module
aliases; each shimmed call substitutes a C expression at the use site; needed
headers appear at the top of the generated C; from-imports and aliasing work.
"""
import pytest

from app.transpiler import TranspileError, transpile


def _c(src: str) -> str:
    code, _ = transpile(src)
    return code


# ── time ───────────────────────────────────────────────────────────────────

def test_time_time_emits_time_h_and_long_cast():
    code = _c("import time\nt = time.time()\n")
    assert "#include <time.h>" in code
    assert "long t = ((long)time(NULL));" in code


def test_time_sleep_emits_unistd_h():
    code = _c("import time\ntime.sleep(2)\n")
    assert "#include <unistd.h>" in code
    assert "sleep(2);" in code


def test_print_of_time_uses_ld_specifier():
    code = _c("import time\nt = time.time()\nprint(t)\n")
    assert 'printf("%ld\\n", t);' in code


# ── math ───────────────────────────────────────────────────────────────────

def test_math_sqrt_emits_math_h_and_double_var():
    code = _c("import math\nx = math.sqrt(16)\n")
    assert "#include <math.h>" in code
    assert "double x = sqrt((double)(16));" in code


def test_math_pi_resolves_to_macro():
    code = _c("import math\ny = math.pi\n")
    assert "#include <math.h>" in code
    assert "double y = M_PI;" in code


def test_math_pow_renders_two_args():
    code = _c("import math\nx = math.pow(2, 10)\n")
    assert "pow((double)(2), (double)(10))" in code


def test_print_double_uses_f_specifier():
    code = _c("import math\nx = math.sqrt(2)\nprint(x)\n")
    assert 'printf("%f\\n", x);' in code


# ── from-imports ───────────────────────────────────────────────────────────

def test_from_math_import_sqrt_and_pi():
    src = "from math import sqrt, pi\nx = sqrt(25)\ny = pi\n"
    code = _c(src)
    assert "#include <math.h>" in code
    assert "double x = sqrt((double)(25));" in code
    assert "double y = M_PI;" in code  # bare name resolves to macro, typed as double


def test_from_math_import_aliased():
    code = _c("from math import sqrt as s\nx = s(9)\n")
    assert "sqrt((double)(9))" in code


def test_import_aliased_module():
    code = _c("import math as m\nx = m.sqrt(4)\n")
    assert "sqrt((double)(4))" in code


# ── random / sys / json ────────────────────────────────────────────────────

def test_random_seed_and_randint():
    code = _c("import random\nrandom.seed(42)\nr = random.randint(1, 6)\n")
    assert "#include <stdlib.h>" in code
    assert "srand((unsigned int)(42));" in code
    assert "int r = ((1) + rand() % (((6) - (1)) + 1));" in code


def test_random_random_returns_double():
    code = _c("import random\nx = random.random()\n")
    assert "double x = ((double)rand() / (double)RAND_MAX);" in code


def test_sys_exit():
    code = _c("import sys\nsys.exit(1)\n")
    assert "#include <stdlib.h>" in code
    assert "exit(1);" in code


def test_json_dumps_emits_helper():
    code = _c("import json\nx = 7\ns = json.dumps(x)\nprint(s)\n")
    # Helper function definition appears in source
    assert "_shim_json_dumps_int" in code
    assert "snprintf(_shim_json_buf" in code
    # Result variable is typed as const char* and printed via %s
    assert "const char* s = _shim_json_dumps_int((int)(x));" in code
    assert 'printf("%s\\n", s);' in code


# ── error paths ────────────────────────────────────────────────────────────

def test_unsupported_module_raises():
    with pytest.raises(TranspileError):
        transpile("import os\n")


def test_unsupported_from_import_raises():
    with pytest.raises(TranspileError):
        transpile("from socket import socket\n")


def test_wildcard_from_import_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("from math import *\n")
    assert "wildcard" in str(ei.value).lower()


def test_unknown_attribute_on_imported_module_falls_through():
    # math.notarealfunc is not in SHIMS — should hit the generic Attribute
    # branch, which emits `math.notarealfunc` and gcc would later fail.
    # We just check the transpile itself succeeds (the failure surfaces at gcc).
    code = _c("import math\nx = math.notarealfunc\n")
    assert "math.notarealfunc" in code


def test_arity_mismatch_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("import math\nx = math.sqrt(1, 2)\n")
    assert "expects 1" in str(ei.value)
