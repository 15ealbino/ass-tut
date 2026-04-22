import pytest
from app.transpiler import TranspileError, transpile


def c(src):
    code, mapping = transpile(src)
    return code, mapping


def test_simple_assignment():
    code, m = c("x = 5")
    assert "int x = 5;" in code
    assert 1 in m


def test_float_assignment():
    code, m = c("x = 3.14")
    assert "double x = 3.14;" in code


def test_string_assignment():
    code, m = c('s = "hello"')
    assert 'char* s = "hello";' in code


def test_augassign():
    code, _ = c("x = 0\nx += 1")
    assert "+= 1;" in code


def test_print_string():
    code, m = c('print("hi")')
    assert 'printf("hi\\n");' in code
    assert 1 in m


def test_print_variable():
    code, _ = c("x = 5\nprint(x)")
    assert "%d" in code


def test_for_range_one_arg():
    code, m = c("for i in range(10):\n    x = i")
    assert "for (int i = 0; i < 10; i += 1)" in code
    assert 1 in m


def test_for_range_two_args():
    code, _ = c("for i in range(2, 5):\n    x = i")
    assert "for (int i = 2; i < 5; i += 1)" in code


def test_while_loop():
    code, m = c("x = 0\nwhile x < 10:\n    x += 1")
    assert "while (x < 10)" in code
    assert 2 in m


def test_if_else():
    code, m = c("x = 1\nif x > 0:\n    y = 1\nelse:\n    y = 0")
    assert "if (x > 0)" in code
    assert "} else {" in code


def test_if_elif():
    code, _ = c("x = 1\nif x == 0:\n    y = 0\nelif x == 1:\n    y = 1")
    assert "else" in code and "if" in code


def test_function_def():
    code, m = c("def add(a, b):\n    return a + b")
    assert "int add(int a, int b)" in code
    assert "return (a + b);" in code


def test_function_call():
    code, _ = c("def sq(n):\n    return n * n\nx = sq(4)")
    assert "sq(4)" in code


def test_binary_ops():
    code, _ = c("x = 2 + 3 * 4 - 1")
    assert "+" in code and "*" in code and "-" in code


def test_comparison():
    code, _ = c("x = 5\ny = x == 5")
    assert "==" in code


def test_bool_and():
    code, _ = c("x = 1\ny = 2\nz = x > 0 and y > 0")
    assert "&&" in code


def test_break_continue():
    code, _ = c("for i in range(5):\n    break\n    continue")
    assert "break;" in code
    assert "continue;" in code


def test_unsupported_construct_raises():
    with pytest.raises(TranspileError):
        transpile("import os")


def test_line_mapping_correctness():
    src = "x = 1\ny = 2\nz = 3"
    _, m = transpile(src)
    assert 1 in m
    assert 2 in m
    assert 3 in m
    # each python line maps to different c lines
    assert m[1] != m[2]
