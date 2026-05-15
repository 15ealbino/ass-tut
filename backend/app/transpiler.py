"""
Python AST → C transpiler with line-number mapping.
Returns (c_source: str, mapping: dict[py_lineno -> list[c_lineno]])
"""
import ast
from typing import Dict, List, Set, Tuple

COLORS = [
    "#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7",
    "#DDA0DD", "#98D8C8", "#F7DC6F", "#BB8FCE", "#82E0AA",
    "#F0B27A", "#85C1E9", "#F1948A", "#73C6B6", "#D2B4DE",
    "#A9CCE3", "#A3E4D7", "#FAD7A0", "#A9DFBF", "#F9E79F",
]

# ── Stdlib-import shim registry ────────────────────────────────────────────
#
# Each entry maps (module_name, attribute) → (c_template, arity, headers, return_type).
# c_template uses {0}, {1}, ... as positional argument placeholders. The
# template is the C expression substituted at the use-site.
#
# Adding a new shim: list the headers it needs and the C return type so
# variable declarations and printf format strings get inferred correctly.

SUPPORTED_MODULES: Set[str] = {"time", "math", "random", "sys", "json"}

SHIMS: Dict[Tuple[str, str], Tuple[str, int, List[str], str]] = {
    ("time", "time"):     ("((long)time(NULL))", 0, ["<time.h>"], "long"),
    ("time", "sleep"):    ("sleep({0})", 1, ["<unistd.h>"], "int"),
    ("math", "sqrt"):     ("sqrt((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "pow"):      ("pow((double)({0}), (double)({1}))", 2, ["<math.h>"], "double"),
    ("math", "floor"):    ("floor((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "ceil"):     ("ceil((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "fabs"):     ("fabs((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "log"):      ("log((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "log2"):     ("log2((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "log10"):    ("log10((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "exp"):      ("exp((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "sin"):      ("sin((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "cos"):      ("cos((double)({0}))", 1, ["<math.h>"], "double"),
    ("math", "tan"):      ("tan((double)({0}))", 1, ["<math.h>"], "double"),
    ("random", "random"):  ("((double)rand() / (double)RAND_MAX)", 0, ["<stdlib.h>"], "double"),
    ("random", "randint"): ("(({0}) + rand() % ((({1}) - ({0})) + 1))", 2, ["<stdlib.h>"], "int"),
    ("random", "seed"):    ("srand((unsigned int)({0}))", 1, ["<stdlib.h>"], "void"),
    ("sys", "exit"):       ("exit({0})", 1, ["<stdlib.h>"], "void"),
    # json.dumps emits a call to a tiny helper function written into the C source.
    ("json", "dumps"):     ("_shim_json_dumps_int((int)({0}))", 1, [], "const char*"),
}

SHIM_CONSTS: Dict[Tuple[str, str], Tuple[str, List[str], str]] = {
    ("math", "pi"):  ("M_PI", ["<math.h>"], "double"),
    ("math", "e"):   ("M_E", ["<math.h>"], "double"),
    ("math", "inf"): ("INFINITY", ["<math.h>"], "double"),
}


class TranspileError(Exception):
    pass

class CEmitter:
    def __init__(self):
        self.lines: List[str] = []
        self.py_to_c: Dict[int, List[int]] = {}
        self._indent = 0

    def _line_no(self) -> int:
        return len(self.lines) + 1

    def emit(self, text: str, py_line: int | None = None):
        c_line = self._line_no()
        self.lines.append("    " * self._indent + text)
        if py_line is not None:
            self.py_to_c.setdefault(py_line, []).append(c_line)

    def indent(self):
        self._indent += 1

    def dedent(self):
        self._indent -= 1

    def source(self) -> str:
        return "\n".join(self.lines)


class Transpiler(ast.NodeVisitor):
    def __init__(self):
        self.emitter = CEmitter()
        self._declared: set = set()
        self._var_types: Dict[str, str] = {}      # var_name -> emitted C type (used by print)
        self._in_func = False
        self._classes: Dict[str, Dict] = {}       # class_name -> {fields, methods}
        self._instance_types: Dict[str, str] = {} # var_name -> class_name
        self._in_method: str | None = None        # class name when inside a method
        # ── Import shim tracking ─────────────────────────────────────────
        # alias -> module name (eg `import time as t` → {"t": "time"})
        self._imports: Dict[str, str] = {}
        # alias -> (module, attr)  (eg `from math import sqrt as s` → {"s": ("math", "sqrt")})
        self._from_imports: Dict[str, Tuple[str, str]] = {}
        self._needed_headers: Set[str] = set()
        self._needs_json_helper = False
        # ── Container tracking ────────────────────────────────────────────
        # name -> element count for list variables (used by len() / for-loops)
        self._list_lengths: Dict[str, int] = {}
        # name -> {keys, vals, helper, keys_arr, vals_arr} for top-level dicts.
        # Dicts live at C file scope so the helper is visible from any function;
        # the dict literal must therefore appear at module top level.
        self._dict_meta: Dict[str, Dict] = {}

    def _type_for(self, node: ast.expr) -> str:
        """Best-effort static type of an expression — used for variable declarations
        and printf format-string selection."""
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                return "int"
            if isinstance(node.value, float):
                return "double"
            if isinstance(node.value, str):
                return "char*"
            return "int"
        if isinstance(node, ast.Call):
            shim = self._shim_for_call(node)
            if shim is not None:
                return shim[3]
            # len() of a list / dict returns int
            if isinstance(node.func, ast.Name) and node.func.id == "len":
                return "int"
        if isinstance(node, ast.Subscript):
            # All supported containers (int lists, int-valued dicts) yield int
            if isinstance(node.value, ast.Name) and (
                    node.value.id in self._list_lengths
                    or node.value.id in self._dict_meta):
                return "int"
            return "int"
        if isinstance(node, ast.Attribute):
            const = self._shim_const_for(node)
            if const is not None:
                return const[2]
        if isinstance(node, ast.Name):
            if node.id in self._from_imports:
                const = SHIM_CONSTS.get(self._from_imports[node.id])
                if const is not None:
                    return const[2]
            return self._var_types.get(node.id, "int")
        return "int"

    def _shim_for_call(self, node: ast.Call) -> Tuple[str, int, List[str], str] | None:
        """Return the SHIMS entry for a call node, or None."""
        key = self._shim_key_for_call(node)
        return SHIMS.get(key) if key is not None else None

    def _shim_key_for_call(self, node: ast.Call) -> Tuple[str, str] | None:
        """Return the (module, attr) key a call resolves to under the import map."""
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in self._imports):
            return (self._imports[node.func.value.id], node.func.attr)
        if isinstance(node.func, ast.Name) and node.func.id in self._from_imports:
            return self._from_imports[node.func.id]
        return None

    def _shim_const_for(self, node: ast.Attribute) -> Tuple[str, List[str], str] | None:
        """Return the SHIM_CONSTS entry for an attribute node like `math.pi`, or None."""
        if (isinstance(node.value, ast.Name)
                and node.value.id in self._imports):
            module = self._imports[node.value.id]
            return SHIM_CONSTS.get((module, node.attr))
        return None

    def _render_shim_call(self, key: Tuple[str, str], call: ast.Call) -> str:
        """Substitute the call's arguments into the shim template."""
        template, arity, _, _ = SHIMS[key]
        if len(call.args) != arity:
            raise TranspileError(
                f"Line {call.lineno}: {key[0]}.{key[1]}() expects {arity} arg(s), got {len(call.args)}"
            )
        rendered_args = [self._expr(a) for a in call.args]
        return template.format(*rendered_args)

    # ── main entry ─────────────────────────────────────────────────────────

    def transpile(self, source: str) -> Tuple[str, Dict[int, List[int]]]:
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            raise TranspileError(f"Python syntax error: {e}")

        # ── First pass: register imports & precompute needed headers ──────
        # Imports must be processed before we emit headers, since we want the
        # shim system to know what's in scope before we visit() the body.
        self._scan_imports_and_shims(tree)
        # Top-level dict literals are hoisted to C file scope; this pass
        # registers them so the helpers exist before main() and any function
        # body that reads from them.
        self._scan_top_level_dicts(tree)

        e = self.emitter
        e.emit('#include <stdio.h>')
        e.emit('#include <string.h>')
        for header in sorted(self._needed_headers - {"<stdio.h>", "<string.h>"}):
            e.emit(f'#include {header}')
        e.emit('')

        # Emit the tiny json.dumps helper if any json.dumps(...) call appears.
        # The static buffer is single-shot per call — chained dumps() inside one
        # expression would clobber each other, but that's an acceptable trade-off
        # for an educational stdio-only shim.
        if self._needs_json_helper:
            e.emit('static char _shim_json_buf[64];')
            e.emit('static const char* _shim_json_dumps_int(int v) {')
            e.indent()
            e.emit('snprintf(_shim_json_buf, sizeof(_shim_json_buf), "%d", v);')
            e.emit('return _shim_json_buf;')
            e.dedent()
            e.emit('}')
            e.emit('')

        # ── Emit file-scope dict storage + lookup helpers ────────────────
        # One static const char*[] of keys, one static int[] of values, and a
        # linear-scan `_shim_dict_<name>_get(const char*)` per dict variable.
        if self._dict_meta:
            self._emit_dict_helpers()

        # ── Emit struct typedefs and method forward-decls for all classes ──
        class_nodes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
        for cls in class_nodes:
            self._register_class(cls)
            self._emit_class_struct(cls)

        # ── Forward-declare top-level functions ────────────────────────────
        funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        for fn in funcs:
            ret = "int"
            args = ", ".join(f"int {a.arg}" for a in fn.args.args)
            e.emit(f"{ret} {fn.name}({args});")

        if funcs or class_nodes:
            e.emit('')

        # ── main() ─────────────────────────────────────────────────────────
        e.emit('int main() {')
        e.indent()

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                self.visit(node)

        e.emit('return 0;')
        e.dedent()
        e.emit('}')
        e.emit('')

        # ── Emit top-level function bodies ─────────────────────────────────
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self._emit_func(node)

        # ── Emit class method bodies ────────────────────────────────────────
        for cls in class_nodes:
            for method in cls.body:
                if isinstance(method, ast.FunctionDef):
                    self._emit_method(cls.name, method)

        return e.source(), e.py_to_c

    # ── Import scanning ─────────────────────────────────────────────────────

    def _scan_imports_and_shims(self, tree: ast.Module):
        """Top-level imports register module aliases; a tree-walk then collects
        every header any used shim would require so they can be emitted upfront.
        """
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name
                    if mod not in SUPPORTED_MODULES:
                        raise TranspileError(
                            f"Line {node.lineno}: unsupported import '{mod}'. "
                            f"Supported modules: {', '.join(sorted(SUPPORTED_MODULES))}"
                        )
                    self._imports[alias.asname or mod] = mod
            elif isinstance(node, ast.ImportFrom):
                mod = node.module
                if mod not in SUPPORTED_MODULES:
                    raise TranspileError(
                        f"Line {node.lineno}: unsupported import from '{mod}'. "
                        f"Supported modules: {', '.join(sorted(SUPPORTED_MODULES))}"
                    )
                for alias in node.names:
                    if alias.name == "*":
                        raise TranspileError(
                            f"Line {node.lineno}: wildcard 'from {mod} import *' is not supported"
                        )
                    self._from_imports[alias.asname or alias.name] = (mod, alias.name)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                shim = self._shim_for_call(node)
                if shim is not None:
                    self._needed_headers.update(shim[2])
                    # Detect json.dumps so the helper is emitted upfront.
                    if (isinstance(node.func, ast.Attribute)
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id in self._imports
                            and self._imports[node.func.value.id] == "json"
                            and node.func.attr == "dumps"):
                        self._needs_json_helper = True
                    elif (isinstance(node.func, ast.Name)
                            and node.func.id in self._from_imports
                            and self._from_imports[node.func.id] == ("json", "dumps")):
                        self._needs_json_helper = True
            elif isinstance(node, ast.Attribute):
                const = self._shim_const_for(node)
                if const is not None:
                    self._needed_headers.update(const[1])

    # ── Container scanning + helpers ────────────────────────────────────────

    @staticmethod
    def _c_str_lit(s: str) -> str:
        escaped = s.replace('\\', '\\\\').replace('"', '\\"')
        return f'"{escaped}"'

    def _scan_top_level_dicts(self, tree: ast.Module):
        """Collect every `name = {...}` top-level assignment so the resulting
        keys/vals arrays and `_get` helper can be emitted at C file scope
        before main(). Inside functions, dicts are rejected at visit time —
        a function-local dict would need a function-local helper, which
        complicates scope rules without much payoff."""
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                raise TranspileError(
                    f"Line {node.lineno}: dict assignment must target a single name"
                )
            name = node.targets[0].id
            d = node.value
            if any(k is None for k in d.keys):
                raise TranspileError(
                    f"Line {node.lineno}: dict-unpacking (**kwargs) is not supported"
                )
            keys: List[str] = []
            vals: List[int] = []
            for k_node, v_node in zip(d.keys, d.values):
                if not (isinstance(k_node, ast.Constant) and isinstance(k_node.value, str)):
                    raise TranspileError(
                        f"Line {node.lineno}: dict keys must be string literals"
                    )
                if (isinstance(v_node, ast.Constant)
                        and isinstance(v_node.value, int)
                        and not isinstance(v_node.value, bool)):
                    vals.append(v_node.value)
                elif (isinstance(v_node, ast.UnaryOp)
                        and isinstance(v_node.op, ast.USub)
                        and isinstance(v_node.operand, ast.Constant)
                        and isinstance(v_node.operand.value, int)):
                    vals.append(-v_node.operand.value)
                else:
                    raise TranspileError(
                        f"Line {node.lineno}: dict values must be int literals"
                    )
                keys.append(k_node.value)
            if name in self._dict_meta:
                raise TranspileError(
                    f"Line {node.lineno}: dict '{name}' is redefined; one dict per name"
                )
            self._dict_meta[name] = {
                "keys": keys,
                "vals": vals,
                "helper":   f"_shim_dict_{name}_get",
                "keys_arr": f"_shim_dict_{name}_keys",
                "vals_arr": f"_shim_dict_{name}_vals",
            }

    def _emit_dict_helpers(self):
        e = self.emitter
        for name, meta in self._dict_meta.items():
            n = len(meta["keys"])
            keys_lit = ", ".join(self._c_str_lit(k) for k in meta["keys"])
            vals_lit = ", ".join(str(v) for v in meta["vals"])
            e.emit(f'static const char* {meta["keys_arr"]}[{n}] = {{{keys_lit}}};')
            e.emit(f'static int {meta["vals_arr"]}[{n}] = {{{vals_lit}}};')
            e.emit(f'static int {meta["helper"]}(const char* key) {{')
            e.indent()
            e.emit(f'for (int i = 0; i < {n}; i++) {{')
            e.indent()
            e.emit(
                f'if (strcmp({meta["keys_arr"]}[i], key) == 0) '
                f'return {meta["vals_arr"]}[i];'
            )
            e.dedent()
            e.emit('}')
            e.emit('return 0;')
            e.dedent()
            e.emit('}')
            e.emit('')

    def _emit_list_assignment(self, name: str, list_node: ast.List, py_line: int):
        if name in self._declared:
            raise TranspileError(
                f"Line {py_line}: list variable '{name}' cannot be reassigned"
            )
        elts = list_node.elts
        n = len(elts)
        if n == 0:
            raise TranspileError(
                f"Line {py_line}: empty list literals are not supported (zero-length C arrays are invalid)"
            )
        rendered: List[str] = []
        for el in elts:
            if isinstance(el, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
                raise TranspileError(
                    f"Line {py_line}: nested containers in list literals are not supported"
                )
            rendered.append(self._expr(el))
        init = ", ".join(rendered)
        self.emitter.emit(f"int {name}[{n}] = {{{init}}};", py_line)
        self._declared.add(name)
        self._var_types[name] = "int[]"
        self._list_lengths[name] = n

    # ── Class helpers ───────────────────────────────────────────────────────

    def _register_class(self, cls: ast.ClassDef):
        fields: List[str] = []
        seen: set = set()
        for method in cls.body:
            if isinstance(method, ast.FunctionDef) and method.name == '__init__':
                for stmt in ast.walk(method):
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if (isinstance(target, ast.Attribute)
                                    and isinstance(target.value, ast.Name)
                                    and target.value.id == 'self'
                                    and target.attr not in seen):
                                fields.append(target.attr)
                                seen.add(target.attr)
                    elif isinstance(stmt, ast.AugAssign):
                        if (isinstance(stmt.target, ast.Attribute)
                                and isinstance(stmt.target.value, ast.Name)
                                and stmt.target.value.id == 'self'
                                and stmt.target.attr not in seen):
                            fields.append(stmt.target.attr)
                            seen.add(stmt.target.attr)
        method_names = [
            m.name for m in cls.body if isinstance(m, ast.FunctionDef)
        ]
        self._classes[cls.name] = {'fields': fields, 'methods': method_names}

    def _emit_class_struct(self, cls: ast.ClassDef):
        e = self.emitter
        info = self._classes[cls.name]
        e.emit(f"typedef struct {{")
        e.indent()
        for field in info['fields']:
            e.emit(f"int {field};")
        e.dedent()
        e.emit(f"}} {cls.name};")
        e.emit('')
        for method in cls.body:
            if not isinstance(method, ast.FunctionDef):
                continue
            sig = self._method_sig(cls.name, method)
            e.emit(f"{sig};")
        e.emit('')

    def _method_sig(self, class_name: str, method: ast.FunctionDef) -> str:
        args_str = ", ".join(
            f"int {a.arg}" for a in method.args.args if a.arg != 'self'
        )
        sep = ", " if args_str else ""
        if method.name == '__init__':
            return f"void {class_name}_init({class_name}* self{sep}{args_str})"
        return f"int {class_name}_{method.name}({class_name}* self{sep}{args_str})"

    def _emit_method(self, class_name: str, method: ast.FunctionDef):
        e = self.emitter
        sig = self._method_sig(class_name, method)
        e.emit(f"{sig} {{", method.lineno)
        e.indent()

        saved_declared = self._declared.copy()
        saved_types = self._instance_types.copy()
        saved_var_types = self._var_types.copy()
        saved_list_lengths = self._list_lengths.copy()
        saved_in_func = self._in_func
        self._declared = {a.arg for a in method.args.args if a.arg != 'self'}
        self._var_types = {a.arg: "int" for a in method.args.args if a.arg != 'self'}
        # Top-level list variables live on main()'s stack and are not visible
        # from another function's frame; reset the table for this scope.
        self._list_lengths = {}
        self._in_method = class_name
        self._in_func = True

        for child in method.body:
            self.visit(child)

        self._in_func = saved_in_func
        self._in_method = None
        self._declared = saved_declared
        self._instance_types = saved_types
        self._var_types = saved_var_types
        self._list_lengths = saved_list_lengths

        if method.name != '__init__':
            e.emit('return 0;', method.end_lineno)
        e.dedent()
        e.emit('}')
        e.emit('')

    # ── Function emit ───────────────────────────────────────────────────────

    def _emit_func(self, node: ast.FunctionDef):
        e = self.emitter
        args = ", ".join(f"int {a.arg}" for a in node.args.args)
        e.emit(f"int {node.name}({args}) {{", node.lineno)
        e.indent()
        saved = self._declared.copy()
        saved_types = self._instance_types.copy()
        saved_var_types = self._var_types.copy()
        saved_list_lengths = self._list_lengths.copy()
        saved_in_func = self._in_func
        saved_in_method = self._in_method
        self._declared = set(a.arg for a in node.args.args)
        self._var_types = {a.arg: "int" for a in node.args.args}
        self._list_lengths = {}
        self._in_func = True
        self._in_method = None  # top-level functions are not inside a class method
        for child in node.body:
            self.visit(child)
        self._in_func = saved_in_func
        self._in_method = saved_in_method
        self._declared = saved
        self._instance_types = saved_types
        self._var_types = saved_var_types
        self._list_lengths = saved_list_lengths
        e.emit('return 0;', node.end_lineno)
        e.dedent()
        e.emit('}')
        e.emit('')

    # ── Visitors ────────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign):
        e = self.emitter
        for target in node.targets:
            # self.attr = val  (inside a method)
            if (isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == 'self'
                    and self._in_method):
                val = self._expr(node.value)
                e.emit(f"self->{target.attr} = {val};", node.lineno)
                continue

            # obj.attr = val  (instance field assignment outside a method)
            if (isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in self._instance_types):
                val = self._expr(node.value)
                e.emit(f"{target.value.id}.{target.attr} = {val};", node.lineno)
                continue

            # Subscript assignment: xs[i] = v  (list write; dict write is banned)
            if isinstance(target, ast.Subscript):
                if not isinstance(target.value, ast.Name):
                    raise TranspileError(
                        f"Line {node.lineno}: subscript assignment must target a named variable"
                    )
                vname = target.value.id
                if vname in self._dict_meta:
                    raise TranspileError(
                        f"Line {node.lineno}: dict assignment (`{vname}[key] = ...`) is not supported"
                    )
                if vname not in self._list_lengths:
                    raise TranspileError(
                        f"Line {node.lineno}: '{vname}' is not a known list; subscript assignment requires a list literal first"
                    )
                self._reject_negative_or_slice(target.slice, node.lineno)
                idx_expr = self._expr(target.slice)
                val = self._expr(node.value)
                e.emit(f"{vname}[{idx_expr}] = {val};", node.lineno)
                continue

            if not isinstance(target, ast.Name):
                raise TranspileError(
                    f"Line {node.lineno}: only simple variable assignment supported"
                )
            name = target.id

            # List literal: xs = [1, 2, 3]
            if isinstance(node.value, ast.List):
                self._emit_list_assignment(name, node.value, node.lineno)
                continue

            # Dict literal: d = {"a": 1, "b": 2}
            if isinstance(node.value, ast.Dict):
                if self._in_func or self._in_method:
                    raise TranspileError(
                        f"Line {node.lineno}: dict literals must be defined at module top level"
                    )
                if name not in self._dict_meta:
                    # The pre-scan handles every well-formed top-level dict
                    # assignment; reaching here means the scan rejected it
                    # and we should not silently emit a placeholder.
                    raise TranspileError(
                        f"Line {node.lineno}: dict '{name}' was not registered during pre-scan"
                    )
                e.emit(f"/* dict {name}: keys/vals + lookup helper at file scope */", node.lineno)
                self._declared.add(name)
                self._var_types[name] = "dict"
                continue

            # Constructor call: n = ClassName(args)
            if (isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name)
                    and node.value.func.id in self._classes):
                class_name = node.value.func.id
                args_str = ", ".join(self._expr(a) for a in node.value.args)
                sep = ", " if args_str else ""
                if name not in self._declared:
                    e.emit(f"{class_name} {name};", node.lineno)
                    self._declared.add(name)
                    self._instance_types[name] = class_name
                e.emit(f"{class_name}_init(&{name}{sep}{args_str});", node.lineno)
                continue

            val = self._expr(node.value)
            if name not in self._declared:
                ctype = self._type_for(node.value)
                e.emit(f"{ctype} {name} = {val};", node.lineno)
                self._declared.add(name)
                self._var_types[name] = ctype
            else:
                e.emit(f"{name} = {val};", node.lineno)

    def _reject_negative_or_slice(self, slice_node: ast.expr, py_line: int):
        if isinstance(slice_node, ast.Slice):
            raise TranspileError(
                f"Line {py_line}: list slicing is not supported"
            )
        if (isinstance(slice_node, ast.Constant)
                and isinstance(slice_node.value, int)
                and slice_node.value < 0):
            raise TranspileError(
                f"Line {py_line}: negative indices are not supported"
            )
        if (isinstance(slice_node, ast.UnaryOp)
                and isinstance(slice_node.op, ast.USub)
                and isinstance(slice_node.operand, ast.Constant)
                and isinstance(slice_node.operand.value, int)):
            raise TranspileError(
                f"Line {py_line}: negative indices are not supported"
            )

    def visit_AugAssign(self, node: ast.AugAssign):
        e = self.emitter
        _AUG_OPS = {ast.Add: "+=", ast.Sub: "-=", ast.Mult: "*=", ast.Div: "/="}
        op = _AUG_OPS.get(type(node.op))
        if op is None:
            raise TranspileError(
                f"Line {node.lineno}: unsupported augmented assignment operator "
                f"{type(node.op).__name__}"
            )
        val = self._expr(node.value)

        # self.attr += val  (inside a method)
        if (isinstance(node.target, ast.Attribute)
                and isinstance(node.target.value, ast.Name)
                and node.target.value.id == 'self'
                and self._in_method):
            e.emit(f"self->{node.target.attr} {op} {val};", node.lineno)
            return

        if not isinstance(node.target, ast.Name):
            raise TranspileError(
                f"Line {node.lineno}: only simple variable augmented assignment supported"
            )
        e.emit(f"{node.target.id} {op} {val};", node.lineno)

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Call):
            self._emit_call(node.value, node.lineno)

    def _emit_call(self, node: ast.Call, py_line: int):
        e = self.emitter

        # Stdlib shim: module.func(args) or `from module import func; func(args)`
        shim = self._shim_for_call(node)
        if shim is not None:
            key = self._shim_key_for_call(node)
            assert key is not None
            rendered = self._render_shim_call(key, node)
            e.emit(f"{rendered};", py_line)
            return

        # Method call: obj.method(args)
        if isinstance(node.func, ast.Attribute):
            obj = node.func.value
            method_name = node.func.attr
            if isinstance(obj, ast.Name) and obj.id in self._instance_types:
                class_name = self._instance_types[obj.id]
                args_str = ", ".join(self._expr(a) for a in node.args)
                sep = ", " if args_str else ""
                e.emit(f"{class_name}_{method_name}(&{obj.id}{sep}{args_str});", py_line)
                return
            # fall through to generic attribute call
            func_expr = self._expr(node.func)
            args_str = ", ".join(self._expr(a) for a in node.args)
            e.emit(f"{func_expr}({args_str});", py_line)
            return

        if isinstance(node.func, ast.Name) and node.func.id == "print":
            args = node.args
            if not args:
                e.emit('printf("\\n");', py_line)
                return
            fmt_parts = []
            c_args = []
            for a in args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    fmt_parts.append(a.value.replace('"', '\\"').replace('%', '%%'))
                    continue
                # Pick the format specifier from the expression's inferred C type.
                # This lets `print(math.sqrt(2))` produce %f and
                # `print(json.dumps(x))` produce %s, rather than always defaulting
                # to %d which would have garbled the output.
                ctype = self._type_for(a)
                spec = {
                    "double": "%f",
                    "float":  "%f",
                    "long":   "%ld",
                    "char*":  "%s",
                    "const char*": "%s",
                }.get(ctype, "%d")
                fmt_parts.append(spec)
                c_args.append(self._expr(a))
            fmt = " ".join(fmt_parts) + "\\n"
            if c_args:
                e.emit(f'printf("{fmt}", {", ".join(c_args)});', py_line)
            else:
                e.emit(f'printf("{fmt}");', py_line)
        else:
            func_name = self._expr(node.func)
            args = ", ".join(self._expr(a) for a in node.args)
            e.emit(f"{func_name}({args});", py_line)

    def visit_For(self, node: ast.For):
        e = self.emitter
        # Iterating a known list variable: walk the array with an index var.
        # Hoist the loop var's declaration into the enclosing scope so its
        # last-value survives the loop (matches Python semantics, and avoids
        # leaving `_declared` pointing at a C identifier that's already out of
        # scope by the next statement).
        if isinstance(node.iter, ast.Name) and node.iter.id in self._list_lengths:
            list_name = node.iter.id
            length = self._list_lengths[list_name]
            var = node.target.id if isinstance(node.target, ast.Name) else "x"
            idx = f"_i_{var}"
            if var not in self._declared:
                e.emit(f"int {var};", node.lineno)
                self._declared.add(var)
                self._var_types[var] = "int"
            e.emit(f"for (int {idx} = 0; {idx} < {length}; {idx}++) {{", node.lineno)
            e.indent()
            e.emit(f"{var} = {list_name}[{idx}];", node.lineno)
            for child in node.body:
                self.visit(child)
            e.dedent()
            e.emit("}", node.end_lineno)
            return
        if not isinstance(node.iter, ast.Call) or not isinstance(node.iter.func, ast.Name):
            raise TranspileError(
                f"Line {node.lineno}: only 'for x in range(...)' or 'for x in <list-variable>' loops supported"
            )
        if node.iter.func.id != "range":
            raise TranspileError(f"Line {node.lineno}: only range() iterator supported")
        var = node.target.id if isinstance(node.target, ast.Name) else "i"
        rargs = node.iter.args
        if len(rargs) == 1:
            start, stop, step = "0", self._expr(rargs[0]), "1"
        elif len(rargs) == 2:
            start, stop, step = self._expr(rargs[0]), self._expr(rargs[1]), "1"
        else:
            start, stop, step = self._expr(rargs[0]), self._expr(rargs[1]), self._expr(rargs[2])
        decl = "" if var in self._declared else "int "
        self._declared.add(var)
        e.emit(f"for ({decl}{var} = {start}; {var} < {stop}; {var} += {step}) {{", node.lineno)
        e.indent()
        for child in node.body:
            self.visit(child)
        e.dedent()
        e.emit("}", node.end_lineno)

    def visit_While(self, node: ast.While):
        e = self.emitter
        cond = self._expr(node.test)
        e.emit(f"while ({cond}) {{", node.lineno)
        e.indent()
        for child in node.body:
            self.visit(child)
        e.dedent()
        e.emit("}", node.end_lineno)

    def visit_If(self, node: ast.If):
        e = self.emitter
        cond = self._expr(node.test)
        e.emit(f"if ({cond}) {{", node.lineno)
        e.indent()
        for child in node.body:
            self.visit(child)
        e.dedent()
        if node.orelse:
            if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                e.emit("} else ", node.orelse[0].lineno)
                elif_node = node.orelse[0]
                cond2 = self._expr(elif_node.test)
                last = e.lines[-1]
                e.lines[-1] = last + f"if ({cond2}) {{"
                e.indent()
                for child in elif_node.body:
                    self.visit(child)
                e.dedent()
                if elif_node.orelse:
                    e.emit("} else {", elif_node.orelse[0].lineno if elif_node.orelse else node.end_lineno)
                    e.indent()
                    for child in elif_node.orelse:
                        self.visit(child)
                    e.dedent()
                e.emit("}", node.end_lineno)
            else:
                e.emit("} else {", node.orelse[0].lineno)
                e.indent()
                for child in node.orelse:
                    self.visit(child)
                e.dedent()
                e.emit("}", node.end_lineno)
        else:
            e.emit("}", node.end_lineno)

    def visit_Return(self, node: ast.Return):
        val = self._expr(node.value) if node.value else "0"
        self.emitter.emit(f"return {val};", node.lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        pass  # handled separately

    def visit_ClassDef(self, node: ast.ClassDef):
        pass  # handled separately

    def visit_Import(self, node: ast.Import):
        # Already registered during the scan phase; the C source only needs
        # the corresponding #include lines emitted at the top of the file.
        pass

    def visit_ImportFrom(self, node: ast.ImportFrom):
        pass

    def visit_Pass(self, node: ast.Pass):
        self.emitter.emit("/* pass */", node.lineno)

    def visit_Break(self, node: ast.Break):
        self.emitter.emit("break;", node.lineno)

    def visit_Continue(self, node: ast.Continue):
        self.emitter.emit("continue;", node.lineno)

    def generic_visit(self, node: ast.AST):
        raise TranspileError(
            f"Unsupported Python construct: {type(node).__name__} at line {getattr(node, 'lineno', '?')}"
        )

    # ── Expression lowering ─────────────────────────────────────────────────

    def _expr(self, node: ast.expr) -> str:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                # Escape backslashes first, then double-quotes, to avoid
                # producing invalid C strings (e.g. "a\" would be unterminated).
                escaped = node.value.replace('\\', '\\\\').replace('"', '\\"')
                return f'"{escaped}"'
            if isinstance(node.value, bool):
                return "1" if node.value else "0"
            return str(node.value)
        if isinstance(node, ast.Name):
            # A from-imported constant (`from math import pi; x = pi`)
            # resolves to the C constant expression, not the bare Python name.
            if node.id in self._from_imports:
                mod_attr = self._from_imports[node.id]
                const = SHIM_CONSTS.get(mod_attr)
                if const is not None:
                    return const[0]
            return node.id
        if isinstance(node, ast.BinOp):
            left = self._expr(node.left)
            right = self._expr(node.right)
            op = {
                ast.Add: "+", ast.Sub: "-", ast.Mult: "*",
                ast.Div: "/", ast.Mod: "%", ast.FloorDiv: "/",
            }.get(type(node.op))
            if op is None:
                raise TranspileError(f"Unsupported binary operator: {type(node.op).__name__}")
            return f"({left} {op} {right})"
        if isinstance(node, ast.UnaryOp):
            operand = self._expr(node.operand)
            if isinstance(node.op, ast.USub):
                return f"(-{operand})"
            if isinstance(node.op, ast.Not):
                return f"(!{operand})"
        if isinstance(node, ast.Compare):
            left = self._expr(node.left)
            parts = []
            for op, comp in zip(node.ops, node.comparators):
                c_op = {
                    ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<",
                    ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
                }.get(type(op), "==")
                parts.append(f"{left} {c_op} {self._expr(comp)}")
                left = self._expr(comp)
            return " && ".join(parts)
        if isinstance(node, ast.BoolOp):
            op = "&&" if isinstance(node.op, ast.And) else "||"
            return f" {op} ".join(self._expr(v) for v in node.values)
        if isinstance(node, ast.Call):
            # Stdlib-shim call (`math.sqrt(x)`, `time.time()`, `sqrt(2)` after a
            # from-import). Resolved first because constructor / instance-method
            # checks below would mis-classify these otherwise.
            key = self._shim_key_for_call(node)
            if key is not None and key in SHIMS:
                return self._render_shim_call(key, node)
            # len() of a known list: emit sizeof-based expression so the
            # length stays a compile-time constant on the C side too.
            if isinstance(node.func, ast.Name) and node.func.id == "len":
                if len(node.args) != 1:
                    raise TranspileError(
                        f"Line {getattr(node, 'lineno', '?')}: len() takes exactly one argument"
                    )
                arg = node.args[0]
                if isinstance(arg, ast.Name) and arg.id in self._dict_meta:
                    raise TranspileError(
                        f"Line {getattr(node, 'lineno', '?')}: len() on a dict is not supported; "
                        f"use a constant in your source instead"
                    )
                if not (isinstance(arg, ast.Name) and arg.id in self._list_lengths):
                    raise TranspileError(
                        f"Line {getattr(node, 'lineno', '?')}: len() argument must be a known list variable"
                    )
                return f"((int)(sizeof({arg.id})/sizeof({arg.id}[0])))"
            # Constructor call inside an expression: ClassName(args)
            if isinstance(node.func, ast.Name) and node.func.id in self._classes:
                raise TranspileError(
                    f"Constructor call in expression context not supported; assign to a variable first"
                )
            # Instance method call in expression context: obj.method(args)
            if (isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in self._instance_types):
                obj_id = node.func.value.id
                class_name = self._instance_types[obj_id]
                method_name = node.func.attr
                args_str = ", ".join(self._expr(a) for a in node.args)
                sep = ", " if args_str else ""
                return f"{class_name}_{method_name}(&{obj_id}{sep}{args_str})"
            func_name = self._expr(node.func)
            args = ", ".join(self._expr(a) for a in node.args)
            return f"{func_name}({args})"
        if isinstance(node, ast.Subscript):
            if not isinstance(node.value, ast.Name):
                raise TranspileError(
                    f"Line {getattr(node, 'lineno', '?')}: subscript target must be a named variable"
                )
            vname = node.value.id
            if vname in self._dict_meta:
                if isinstance(node.slice, ast.Slice):
                    raise TranspileError(
                        f"Line {getattr(node, 'lineno', '?')}: dict slicing is not supported"
                    )
                key_expr = self._expr(node.slice)
                return f'{self._dict_meta[vname]["helper"]}({key_expr})'
            if vname in self._list_lengths:
                self._reject_negative_or_slice(node.slice, getattr(node, 'lineno', 0) or 0)
                idx_expr = self._expr(node.slice)
                return f"{vname}[{idx_expr}]"
            raise TranspileError(
                f"Line {getattr(node, 'lineno', '?')}: subscript on '{vname}' but it is not a known list or dict"
            )
        if isinstance(node, ast.Attribute):
            # Stdlib constant (`math.pi`).
            const = self._shim_const_for(node)
            if const is not None:
                return const[0]
            # self.attr inside a method → pointer dereference
            if (isinstance(node.value, ast.Name)
                    and node.value.id == 'self'
                    and self._in_method):
                return f"self->{node.attr}"
            obj = self._expr(node.value)
            return f"{obj}.{node.attr}"
        if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
            raise TranspileError(
                f"Line {getattr(node, 'lineno', '?')}: container literals are only supported on the right-hand side of a top-level assignment"
            )
        raise TranspileError(f"Unsupported expression: {type(node).__name__}")


def transpile(python_source: str) -> Tuple[str, Dict[int, List[int]]]:
    t = Transpiler()
    return t.transpile(python_source)


def build_line_map(
    python_lines: List[str],
    py_to_c: Dict[int, List[int]],
    c_to_asm: Dict[int, List[int]],
) -> Dict[int, dict]:
    result = {}
    for py_lineno, c_linenos in py_to_c.items():
        asm_linenos: List[int] = []
        for cl in c_linenos:
            asm_linenos.extend(c_to_asm.get(cl, []))
        color = COLORS[(py_lineno - 1) % len(COLORS)]
        result[py_lineno] = {
            "c_lines": sorted(set(c_linenos)),
            "asm_lines": sorted(set(asm_linenos)),
            "color": color,
        }
    return result
