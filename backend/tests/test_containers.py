"""
Tests for the list-and-dict-literal support added to the AST→C transpiler.

The unit tests pin the exact emitted C — both because the educational value of
the tool depends on the C looking the way the docs say it looks, and because
several existing rejection tests in test_invalid_transpile.py rely on the
"range" word appearing in the for-loop error message; this file pins that
regression too.

The single async test exercises the full /compile pipeline (transpiler → gcc →
asm line map) with a small program that uses both lists and dicts.
"""
import pytest

from app.transpiler import TranspileError, transpile


def _c(src: str) -> str:
    code, _ = transpile(src)
    return code


# ────────────────────────────────────────────────────────────────────────────
# Lists — emission shape
# ────────────────────────────────────────────────────────────────────────────


def test_list_literal_emits_fixed_size_int_array():
    code = _c("xs = [1, 2, 3]\n")
    assert "int xs[3] = {1, 2, 3};" in code


def test_list_index_read_emits_array_subscript():
    code = _c("xs = [10, 20, 30]\ny = xs[1]\n")
    assert "int y = xs[1];" in code


def test_list_index_write_emits_array_subscript_assignment():
    code = _c("xs = [10, 20, 30]\nxs[0] = 99\n")
    assert "xs[0] = 99;" in code


def test_len_on_list_emits_sizeof_expression():
    code = _c("xs = [1, 2, 3, 4]\nn = len(xs)\n")
    assert "int n = ((int)(sizeof(xs)/sizeof(xs[0])));" in code


def test_for_over_list_hoists_decl_then_emits_indexed_for():
    code = _c("xs = [10, 20, 30]\nfor v in xs:\n    print(v)\n")
    # Loop var is hoisted to the enclosing scope so it survives past the loop.
    assert "int v;" in code
    # Index var is named `_i_<target>`; loop bound comes from the captured len.
    assert "for (int _i_v = 0; _i_v < 3; _i_v++) {" in code
    # Inside the loop body, the target is just an assignment (not redeclared).
    assert "v = xs[_i_v];" in code


def test_print_of_list_element_uses_d_format():
    # Subscript expression's type inference must reach %d, not the fallback.
    code = _c("xs = [10, 20, 30]\nprint(xs[0])\n")
    assert 'printf("%d\\n", xs[0]);' in code


def test_list_inside_function_scope():
    code = _c(
        "def f():\n"
        "    ys = [1, 2, 3]\n"
        "    return ys[0]\n"
        "\n"
        "x = f()\n"
    )
    # Array declaration appears inside the function body, not at file scope.
    assert "int f()" in code
    assert "int ys[3] = {1, 2, 3};" in code
    assert "return ys[0];" in code


def test_list_with_non_constant_int_elements_lowers_each_through_expr():
    # Local int variables are valid C99 auto-array initializers, so each
    # element is just the C expression for that name.
    code = _c("a = 1\nb = 2\nc = 3\nxs = [a, b, c]\n")
    assert "int xs[3] = {a, b, c};" in code


def test_list_len_is_compile_time_constant():
    # The sizeof-based emission lets `len(xs)` participate in static contexts.
    # We do not assert a specific value — only that the produced expression
    # is purely a sizeof divide, with no runtime helper calls.
    code = _c("xs = [1, 2, 3, 4, 5]\nn = len(xs)\n")
    assert "sizeof(xs)" in code
    assert "sizeof(xs[0])" in code
    assert "_shim" not in code.split("int n =", 1)[1].split(";", 1)[0]


# ────────────────────────────────────────────────────────────────────────────
# Dicts — emission shape
# ────────────────────────────────────────────────────────────────────────────


def test_dict_literal_hoists_keys_vals_and_helper_to_file_scope():
    code = _c('d = {"a": 1, "b": 2}\n')
    assert 'static const char* _shim_dict_d_keys[2] = {"a", "b"};' in code
    assert "static int _shim_dict_d_vals[2] = {1, 2};" in code
    assert "static int _shim_dict_d_get(const char* key) {" in code


def test_dict_helpers_appear_before_main():
    code = _c('d = {"a": 1}\n')
    helper_pos = code.find("_shim_dict_d_get")
    main_pos = code.find("int main()")
    assert helper_pos != -1 and main_pos != -1
    assert helper_pos < main_pos, (
        "dict helper must be declared above main() so it is in scope at use"
    )


def test_dict_assignment_site_emits_only_a_comment():
    code = _c('d = {"a": 1}\n')
    # The hoist means main() carries a marker comment, not a C declaration.
    assert "/* dict d:" in code
    # And no `int d = ...` / `char d = ...` etc. declaration was emitted.
    main_body = code.split("int main()", 1)[1]
    assert "int d " not in main_body
    assert "char d " not in main_body


def test_dict_subscript_read_calls_the_named_helper():
    code = _c('d = {"a": 1, "b": 2}\nv = d["a"]\n')
    assert 'int v = _shim_dict_d_get("a");' in code


def test_multiple_dicts_each_get_their_own_helper():
    code = _c('d1 = {"a": 1}\nd2 = {"b": 2}\n')
    assert "_shim_dict_d1_get" in code
    assert "_shim_dict_d2_get" in code
    # The two helpers are independent declarations.
    assert code.count("static int _shim_dict_d1_get") == 1
    assert code.count("static int _shim_dict_d2_get") == 1


def test_dict_keys_with_quotes_and_backslashes_are_c_escaped():
    # Python source contains a literal `"` and a literal `\` inside each key.
    # In the emitted C the keys array must contain proper C escape sequences
    # so the string literals parse — and the use site must escape identically.
    code = _c('d = {"a\\"b": 1, "x\\\\y": 2}\nv = d["a\\"b"]\n')
    assert r'{"a\"b", "x\\y"}' in code
    assert 'int v = _shim_dict_d_get("a\\"b");' in code


def test_dict_int_value_supports_negative_literals():
    # `-1` is parsed as UnaryOp(USub, Constant(1)); pre-scan still records -1
    # as the stored value so the C initializer is a plain literal.
    code = _c('d = {"a": -1, "b": 2}\n')
    assert "static int _shim_dict_d_vals[2] = {-1, 2};" in code


# ────────────────────────────────────────────────────────────────────────────
# Rejection paths
# ────────────────────────────────────────────────────────────────────────────


def test_empty_list_literal_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = []\n")
    assert "empty list" in str(ei.value).lower()


def test_list_reassignment_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [1, 2]\nxs = [3, 4]\n")
    assert "reassigned" in str(ei.value).lower()


def test_dict_subscript_write_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": 1}\nd["a"] = 2\n')
    msg = str(ei.value).lower()
    assert "dict assignment" in msg or "not supported" in msg


def test_len_on_dict_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": 1}\nn = len(d)\n')
    assert "dict" in str(ei.value).lower()


def test_negative_index_read_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [1, 2, 3]\nv = xs[-1]\n")
    assert "negative" in str(ei.value).lower()


def test_negative_index_write_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [1, 2, 3]\nxs[-1] = 9\n")
    assert "negative" in str(ei.value).lower()


def test_list_slice_read_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [1, 2, 3]\ny = xs[1:2]\n")
    assert "slic" in str(ei.value).lower()


def test_list_slice_write_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [1, 2, 3]\nxs[1:2] = [9]\n")
    assert "slic" in str(ei.value).lower()


def test_non_string_dict_key_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("d = {1: 2}\n")
    assert "string literal" in str(ei.value).lower()


def test_non_int_dict_value_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": "b"}\n')
    assert "int literal" in str(ei.value).lower()


def test_dict_inside_function_body_raises():
    src = (
        "def f():\n"
        '    d = {"a": 1}\n'
        '    return d["a"]\n'
    )
    with pytest.raises(TranspileError) as ei:
        transpile(src)
    assert "top level" in str(ei.value).lower()


def test_bare_list_literal_in_expression_raises():
    # `print([1, 2, 3])` should not silently degrade — emit a clear error.
    with pytest.raises(TranspileError) as ei:
        transpile("print([1, 2, 3])\n")
    msg = str(ei.value).lower()
    assert "container literal" in msg or "list" in msg


def test_subscript_read_on_unknown_name_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("y = unknown[0]\n")
    msg = str(ei.value).lower()
    assert "unknown" in msg or "not a known list" in msg


def test_subscript_write_on_unknown_name_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("unknown[0] = 1\n")
    msg = str(ei.value).lower()
    assert "not a known list" in msg or "unknown" in msg


def test_nested_list_literal_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [[1, 2], [3, 4]]\n")
    assert "nested" in str(ei.value).lower()


# ────────────────────────────────────────────────────────────────────────────
# Existing guarantees that the container feature must not erode
# ────────────────────────────────────────────────────────────────────────────


def test_for_over_list_literal_still_raises_with_range_hint():
    # The visit_For guard must still mention "range" — test_invalid_transpile
    # relies on this exact wording.
    with pytest.raises(TranspileError) as ei:
        transpile("for x in [1, 2, 3]:\n    y = x\n")
    assert "range" in str(ei.value).lower()


def test_for_over_undeclared_variable_still_raises_with_range_hint():
    with pytest.raises(TranspileError) as ei:
        transpile("for x in items:\n    y = x\n")
    assert "range" in str(ei.value).lower()


def test_list_comprehension_still_raises():
    with pytest.raises(TranspileError):
        transpile("squares = [x * x for x in range(5)]\n")


def test_dict_comprehension_still_raises():
    with pytest.raises(TranspileError):
        transpile("d = {x: x * 2 for x in range(3)}\n")


def test_set_comprehension_still_raises():
    with pytest.raises(TranspileError):
        transpile("s = {x for x in range(3)}\n")


# ────────────────────────────────────────────────────────────────────────────
# End-to-end: /compile must drive the full pipeline on a list+dict program
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_compile_list_and_dict_program_end_to_end(client):
    """The full /compile pipeline (transpile → gcc -S → asm line map) must
    succeed on a program using both containers, and must return a populated
    line_map keyed by Python line number."""
    src = (
        'xs = [10, 20, 30]\n'
        'total = 0\n'
        'for v in xs:\n'
        '    total += v\n'
        'd = {"a": 1, "b": 2}\n'
        'pick = d["b"]\n'
        'print(total)\n'
        'print(pick)\n'
    )
    r = await client.post("/compile", json={"code": src})
    assert r.status_code == 200, r.text
    body = r.json()
    # Generated C contains both the array initializer and the dict helper.
    assert "int xs[3] = {10, 20, 30};" in body["c_code"]
    assert "_shim_dict_d_get" in body["c_code"]
    # Pipeline reached gcc and produced non-empty asm.
    assert len(body["asm_code"]) > 0
    assert len(body["asm_lines"]) > 0
    # Several Python lines should appear in line_map (JSON-coerced to str keys).
    assert "1" in body["line_map"]   # xs = [...]
    assert "3" in body["line_map"]   # for v in xs:
    assert "5" in body["line_map"]   # d = {...}
