"""
Comprehensive tests for complex Python constructs in the transpiler.

Organised into sections:
  1.  Classes — struct emit, init, methods, field access, augmented assignment
  2.  Inheritance — single and multiple (bases silently ignored by design)
  3.  Class variables and decorators — silently skipped, no error raised
  4.  Complex data structures — tuples, sets, nested containers all rejected
  5.  Comprehensions — direct-transpile checks for list/dict/set/generator
  6.  Recursive and mutually-recursive functions
  7.  Unsupported constructs — async def, nested def, unavailable imports,
      walrus operator, ternary expression

For each construct the test asserts either:
  a) valid C output AND at least one entry in the line map, or
  b) a clean TranspileError with a descriptive (non-empty) message.

None of these tests duplicate coverage already in test_transpiler.py,
test_invalid_transpile.py, or test_containers.py.
"""

import pytest
from app.transpiler import TranspileError, transpile


# ── helpers ───────────────────────────────────────────────────────────────────

def _c(src: str) -> str:
    code, _ = transpile(src)
    return code


def _map(src: str) -> dict:
    _, m = transpile(src)
    return m


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Classes
# ═══════════════════════════════════════════════════════════════════════════════


def test_class_emits_typedef_struct():
    code = _c(
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
    )
    assert "typedef struct {" in code
    assert "int x;" in code
    assert "int y;" in code
    assert "} Point;" in code


def test_class_init_emits_void_function():
    code = _c(
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
    )
    assert "void Point_init(Point* self, int x, int y)" in code


def test_class_method_emits_int_function():
    code = _c(
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
        "    def get_x(self):\n"
        "        return self.x\n"
    )
    assert "int Point_get_x(Point* self)" in code
    assert "return self->x;" in code


def test_class_field_access_uses_arrow_notation():
    code = _c(
        "class Box:\n"
        "    def __init__(self, w, h):\n"
        "        self.w = w\n"
        "        self.h = h\n"
        "    def area(self):\n"
        "        return self.w * self.h\n"
    )
    assert "return (self->w * self->h);" in code


def test_class_instantiation_emits_struct_decl_and_init_call():
    code = _c(
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
        "p = Point(3, 4)\n"
    )
    assert "Point p;" in code
    assert "Point_init(&p, 3, 4);" in code


def test_class_method_call_emits_prefixed_function_call():
    code = _c(
        "class Counter:\n"
        "    def __init__(self):\n"
        "        self.n = 0\n"
        "    def tick(self):\n"
        "        self.n += 1\n"
        "c = Counter()\n"
        "c.tick()\n"
    )
    assert "Counter_tick(&c);" in code


def test_class_augassign_on_self_emits_arrow_augassign():
    code = _c(
        "class Counter:\n"
        "    def __init__(self):\n"
        "        self.n = 0\n"
        "    def tick(self):\n"
        "        self.n += 1\n"
    )
    assert "self->n += 1;" in code


def test_class_conditional_in_method_uses_arrow_notation():
    code = _c(
        "class Point:\n"
        "    def __init__(self, x):\n"
        "        self.x = x\n"
        "    def positive(self):\n"
        "        if self.x > 0:\n"
        "            return 1\n"
        "        return 0\n"
    )
    assert "if (self->x > 0)" in code


def test_class_method_with_extra_param_emits_correct_signature():
    code = _c(
        "class Rect:\n"
        "    def __init__(self, w, h):\n"
        "        self.w = w\n"
        "        self.h = h\n"
        "    def scale(self, f):\n"
        "        self.w *= f\n"
        "        self.h *= f\n"
    )
    assert "int Rect_scale(Rect* self, int f)" in code
    assert "self->w *= f;" in code
    assert "self->h *= f;" in code


def test_class_multiple_methods_all_emitted():
    code = _c(
        "class Rect:\n"
        "    def __init__(self, w, h):\n"
        "        self.w = w\n"
        "        self.h = h\n"
        "    def area(self):\n"
        "        return self.w * self.h\n"
        "    def perimeter(self):\n"
        "        return self.w + self.h\n"
    )
    assert "int Rect_area(Rect* self)" in code
    assert "int Rect_perimeter(Rect* self)" in code
    assert "return (self->w * self->h);" in code
    assert "return (self->w + self->h);" in code


def test_class_forward_declaration_appears_before_method_body():
    code = _c(
        "class Foo:\n"
        "    def __init__(self):\n"
        "        self.v = 0\n"
        "    def get(self):\n"
        "        return self.v\n"
    )
    fwd_pos = code.find("int Foo_get(Foo* self);")
    body_pos = code.find("int Foo_get(Foo* self) {")
    assert fwd_pos != -1 and body_pos != -1
    assert fwd_pos < body_pos, "Forward declaration must precede definition"


def test_two_classes_both_get_structs():
    code = _c(
        "class A:\n"
        "    def __init__(self, x):\n"
        "        self.x = x\n"
        "class B:\n"
        "    def __init__(self, y):\n"
        "        self.y = y\n"
    )
    assert "} A;" in code
    assert "} B;" in code


def test_class_line_map_includes_method_definition_lines():
    src = (
        "class Point:\n"              # 1
        "    def __init__(self, x):\n"  # 2
        "        self.x = x\n"        # 3
        "    def get_x(self):\n"      # 4
        "        return self.x\n"     # 5
    )
    m = _map(src)
    # Both method definition lines must produce C and appear in the map.
    assert 2 in m, "__init__ line should be in line map"
    assert 4 in m, "get_x line should be in line map"


def test_class_line_map_includes_init_body_lines():
    src = (
        "class Point:\n"              # 1
        "    def __init__(self, x, y):\n"  # 2
        "        self.x = x\n"        # 3
        "        self.y = y\n"        # 4
    )
    m = _map(src)
    assert 3 in m
    assert 4 in m
    # Each field assignment maps to a distinct C line.
    assert m[3] != m[4]


def test_class_instantiation_line_in_map():
    src = (
        "class Pt:\n"                 # 1
        "    def __init__(self, x):\n"  # 2
        "        self.x = x\n"        # 3
        "p = Pt(7)\n"                 # 4
    )
    m = _map(src)
    assert 4 in m
    # Both `Pt p;` and `Pt_init(&p, 7);` are emitted for line 4.
    assert len(m[4]) >= 2


def test_class_for_loop_in_method():
    code = _c(
        "class Adder:\n"
        "    def __init__(self, n):\n"
        "        self.n = n\n"
        "    def add_range(self, limit):\n"
        "        for i in range(limit):\n"
        "            self.n += i\n"
    )
    assert "for (int i = 0; i < limit; i += 1)" in code
    assert "self->n += i;" in code


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Inheritance (bases are silently ignored — by design)
# ═══════════════════════════════════════════════════════════════════════════════


def test_single_inheritance_does_not_raise():
    code = _c(
        "class Animal:\n"
        "    def __init__(self, name):\n"
        "        self.name = name\n"
        "class Dog(Animal):\n"
        "    def __init__(self, name, breed):\n"
        "        self.name = name\n"
        "        self.breed = breed\n"
    )
    assert "} Animal;" in code
    assert "} Dog;" in code


def test_single_inheritance_child_struct_contains_own_fields():
    code = _c(
        "class Animal:\n"
        "    def __init__(self, name):\n"
        "        self.name = name\n"
        "class Dog(Animal):\n"
        "    def __init__(self, name, breed):\n"
        "        self.name = name\n"
        "        self.breed = breed\n"
    )
    # Isolate the Dog struct body (text between the last `typedef struct {`
    # and `} Dog;`).
    before_dog_close = code.split("} Dog;")[0]
    dog_body = before_dog_close.rsplit("typedef struct {", 1)[-1]
    assert "int name;" in dog_body
    assert "int breed;" in dog_body


def test_multiple_inheritance_does_not_raise():
    code = _c(
        "class A:\n"
        "    def __init__(self, x):\n"
        "        self.x = x\n"
        "class B:\n"
        "    def __init__(self, y):\n"
        "        self.y = y\n"
        "class C(A, B):\n"
        "    def __init__(self, x, y, z):\n"
        "        self.x = x\n"
        "        self.y = y\n"
        "        self.z = z\n"
    )
    assert "} C;" in code
    before_c_close = code.split("} C;")[0]
    c_body = before_c_close.rsplit("typedef struct {", 1)[-1]
    assert "int z;" in c_body


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Class variables and decorators (both silently ignored)
# ═══════════════════════════════════════════════════════════════════════════════


def test_class_variable_does_not_raise():
    # Class-level assignments (not `self.x`) are not visited and not emitted.
    code = _c(
        "class Counter:\n"
        "    count = 0\n"
        "    def __init__(self):\n"
        "        self.value = 0\n"
    )
    assert "} Counter;" in code


def test_class_variable_not_in_struct():
    code = _c(
        "class Counter:\n"
        "    count = 0\n"
        "    def __init__(self):\n"
        "        self.value = 0\n"
    )
    struct_body = code.split("} Counter;")[0].rsplit("typedef struct {", 1)[-1]
    # `count` was a class variable, not a self-assignment, so it must not be a field.
    assert "int count;" not in struct_body
    assert "int value;" in struct_body


def test_annotated_class_body_silently_skipped():
    # PEP-526 annotations in class body (dataclass-style) are AnnAssign nodes;
    # they are not visited and produce no error.
    code = _c(
        "class Coord:\n"
        "    x: int\n"
        "    y: int\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
    )
    assert "} Coord;" in code
    struct_body = code.split("} Coord;")[0].rsplit("typedef struct {", 1)[-1]
    assert "int x;" in struct_body
    assert "int y;" in struct_body


def test_function_decorator_silently_ignored():
    # Decorator on a top-level function is not processed; the function is emitted normally.
    code = _c(
        "def identity(f):\n"
        "    return f\n"
        "@identity\n"
        "def square(x):\n"
        "    return x * x\n"
    )
    assert "int square(int x)" in code
    assert "return (x * x);" in code


def test_staticmethod_decorator_on_class_method_does_not_raise():
    # @staticmethod is not processed; the method is emitted with a (superfluous)
    # `self*` parameter — this is expected and documented behaviour.
    code = _c(
        "class MathHelper:\n"
        "    def __init__(self):\n"
        "        self.v = 0\n"
        "    @staticmethod\n"
        "    def square(x):\n"
        "        return x * x\n"
    )
    assert "MathHelper_square" in code


def test_classmethod_decorator_on_class_method_does_not_raise():
    # @classmethod is not processed; `cls` is treated as a plain int parameter.
    code = _c(
        "class Foo:\n"
        "    def __init__(self):\n"
        "        self.v = 0\n"
        "    @classmethod\n"
        "    def create(cls):\n"
        "        return 0\n"
    )
    assert "Foo_create" in code


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Complex data structures — all rejected cleanly
# ═══════════════════════════════════════════════════════════════════════════════


def test_tuple_literal_raises():
    with pytest.raises(TranspileError):
        transpile("t = (1, 2, 3)\n")


def test_tuple_literal_error_is_nonempty():
    with pytest.raises(TranspileError) as ei:
        transpile("t = (1, 2, 3)\n")
    assert len(str(ei.value)) > 0


def test_set_literal_raises():
    with pytest.raises(TranspileError):
        transpile("s = {1, 2, 3}\n")


def test_set_literal_error_is_nonempty():
    with pytest.raises(TranspileError) as ei:
        transpile("s = {1, 2, 3}\n")
    assert len(str(ei.value)) > 0


def test_nested_dict_value_is_dict_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": {"b": 1}}\n')
    assert "int literal" in str(ei.value).lower()


def test_nested_dict_value_is_expression_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": 1 + 2}\n')
    assert "int literal" in str(ei.value).lower()


def test_dict_value_is_variable_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('x = 5\nd = {"a": x}\n')
    assert "int literal" in str(ei.value).lower()


def test_list_of_dicts_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('xs = [{"a": 1}, {"b": 2}]\n')
    assert "nested" in str(ei.value).lower()


def test_list_of_tuples_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [(1, 2), (3, 4)]\n")
    assert len(str(ei.value)) > 0


def test_list_of_sets_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("xs = [{1, 2}, {3, 4}]\n")
    assert len(str(ei.value)) > 0


def test_tuple_in_function_return_raises():
    with pytest.raises(TranspileError):
        transpile("def f():\n    return (1, 2)\n")


def test_set_as_len_argument_raises():
    with pytest.raises(TranspileError):
        transpile("x = len({1, 2, 3})\n")


def test_dict_with_list_value_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": [1, 2]}\n')
    assert "int literal" in str(ei.value).lower()


def test_dict_with_tuple_value_raises():
    with pytest.raises(TranspileError) as ei:
        transpile('d = {"a": (1, 2)}\n')
    assert "int literal" in str(ei.value).lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Comprehensions — direct TranspileError checks (not API-level)
# ═══════════════════════════════════════════════════════════════════════════════


def test_generator_expression_in_assignment_raises():
    with pytest.raises(TranspileError):
        transpile("g = (x for x in range(5))\n")


def test_generator_expression_error_is_nonempty():
    with pytest.raises(TranspileError) as ei:
        transpile("g = (x for x in range(5))\n")
    assert len(str(ei.value)) > 0


def test_nested_list_comprehension_raises():
    with pytest.raises(TranspileError):
        transpile("matrix = [[j for j in range(3)] for i in range(3)]\n")


def test_comprehension_inside_function_raises():
    with pytest.raises(TranspileError):
        transpile("def f(n):\n    return [x for x in range(n)]\n")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Recursive and mutually-recursive functions
# ═══════════════════════════════════════════════════════════════════════════════


def test_simple_recursive_function_transpiles():
    code = _c(
        "def factorial(n):\n"
        "    if n <= 1:\n"
        "        return 1\n"
        "    return n * factorial(n - 1)\n"
        "x = factorial(5)\n"
    )
    assert "int factorial(int n)" in code
    assert "factorial((n - 1))" in code


def test_recursive_function_forward_declared_before_main():
    code = _c(
        "def fib(n):\n"
        "    if n <= 1:\n"
        "        return n\n"
        "    return fib(n - 1) + fib(n - 2)\n"
    )
    fwd_pos = code.find("int fib(int n);")
    main_pos = code.find("int main()")
    assert fwd_pos != -1 and main_pos != -1
    assert fwd_pos < main_pos, "Forward declaration must precede main()"


def test_mutually_recursive_functions_transpile():
    code = _c(
        "def is_even(n):\n"
        "    if n == 0:\n"
        "        return 1\n"
        "    return is_odd(n - 1)\n"
        "def is_odd(n):\n"
        "    if n == 0:\n"
        "        return 0\n"
        "    return is_even(n - 1)\n"
        "x = is_even(4)\n"
    )
    assert "int is_even(int n)" in code
    assert "int is_odd(int n)" in code
    assert "is_odd((n - 1))" in code
    assert "is_even((n - 1))" in code


def test_mutually_recursive_both_forward_declared():
    code = _c(
        "def ping(n):\n"
        "    if n == 0:\n"
        "        return 0\n"
        "    return pong(n - 1)\n"
        "def pong(n):\n"
        "    if n == 0:\n"
        "        return 0\n"
        "    return ping(n - 1)\n"
    )
    main_pos = code.find("int main()")
    ping_fwd = code.find("int ping(int n);")
    pong_fwd = code.find("int pong(int n);")
    assert ping_fwd < main_pos
    assert pong_fwd < main_pos


def test_recursive_function_line_map_covers_body():
    src = (
        "def countdown(n):\n"           # 1
        "    if n <= 0:\n"              # 2
        "        return 0\n"            # 3
        "    return countdown(n - 1)\n" # 4
        "x = countdown(10)\n"          # 5
    )
    m = _map(src)
    assert 2 in m  # if statement
    assert 3 in m  # base-case return
    assert 4 in m  # recursive return
    assert 5 in m  # call site


def test_recursive_function_on_unknown_subscript_raises():
    # Subscripting a parameter that is not a declared list/dict must raise.
    with pytest.raises(TranspileError) as ei:
        transpile(
            "def head(xs):\n"
            "    return xs[0]\n"
        )
    msg = str(ei.value).lower()
    assert "not a known list" in msg or "unknown" in msg


def test_recursive_function_calling_class_method():
    # A recursive helper combined with an instantiated class.
    code = _c(
        "def sum_to(n):\n"
        "    if n <= 0:\n"
        "        return 0\n"
        "    return n + sum_to(n - 1)\n"
        "class Wrapper:\n"
        "    def __init__(self, v):\n"
        "        self.v = v\n"
        "    def compute(self, n):\n"
        "        return sum_to(n)\n"
    )
    assert "int sum_to(int n)" in code
    assert "sum_to(n)" in code
    assert "int Wrapper_compute(Wrapper* self, int n)" in code


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Unsupported constructs
# ═══════════════════════════════════════════════════════════════════════════════


def test_async_function_def_raises():
    with pytest.raises(TranspileError):
        transpile("async def fetch():\n    pass\n")


def test_async_function_error_is_nonempty():
    with pytest.raises(TranspileError) as ei:
        transpile("async def fetch():\n    pass\n")
    assert len(str(ei.value)) > 0


def test_nested_function_def_raises():
    with pytest.raises(TranspileError):
        transpile(
            "def outer():\n"
            "    def inner():\n"
            "        return 1\n"
            "    return inner()\n"
        )


def test_nested_class_def_in_function_raises():
    with pytest.raises(TranspileError):
        transpile(
            "def factory():\n"
            "    class Inner:\n"
            "        pass\n"
            "    return 0\n"
        )


def test_dataclass_import_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("from dataclasses import dataclass\n")
    assert "dataclasses" in str(ei.value).lower()


def test_typing_import_raises():
    with pytest.raises(TranspileError) as ei:
        transpile("from typing import List\n")
    assert "typing" in str(ei.value).lower()


def test_ternary_expression_raises():
    # ast.IfExp is not handled by _expr.
    with pytest.raises(TranspileError):
        transpile("x = 1\ny = x if x > 0 else 0\n")


def test_ternary_expression_error_is_nonempty():
    with pytest.raises(TranspileError) as ei:
        transpile("x = 1\ny = x if x > 0 else 0\n")
    assert len(str(ei.value)) > 0


def test_walrus_operator_raises():
    # ast.NamedExpr (:=) is not handled by _expr.
    with pytest.raises(TranspileError):
        transpile("x = 5\nif (y := x + 1) > 0:\n    print(y)\n")
