"""
Python AST → C transpiler with line-number mapping.
Returns (c_source: str, mapping: dict[py_lineno -> list[c_lineno]])
"""
import ast
from typing import Dict, List, Tuple

COLORS = [
    "#FF6B6B", "#4ECDC4", "#45B7D1", "#96CEB4", "#FFEAA7",
    "#DDA0DD", "#98D8C8", "#F7DC6F", "#BB8FCE", "#82E0AA",
    "#F0B27A", "#85C1E9", "#F1948A", "#73C6B6", "#D2B4DE",
    "#A9CCE3", "#A3E4D7", "#FAD7A0", "#A9DFBF", "#F9E79F",
]

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


def _type_for(node: ast.expr) -> str:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, float):
            return "double"
        if isinstance(node.value, str):
            return "char*"
    return "int"


class Transpiler(ast.NodeVisitor):
    def __init__(self):
        self.emitter = CEmitter()
        self._declared: set = set()
        self._in_func = False

    def transpile(self, source: str) -> Tuple[str, Dict[int, List[int]]]:
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            raise TranspileError(f"Python syntax error: {e}")

        e = self.emitter
        e.emit('#include <stdio.h>')
        e.emit('#include <string.h>')
        e.emit('')

        # Collect top-level function defs first so we can forward-declare
        funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        for fn in funcs:
            ret = "int"
            args = ", ".join(f"int {a.arg}" for a in fn.args.args)
            e.emit(f"{ret} {fn.name}({args});")

        if funcs:
            e.emit('')

        e.emit('int main() {')
        e.indent()

        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                self.visit(node)

        e.emit('return 0;')
        e.dedent()
        e.emit('}')
        e.emit('')

        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                self._emit_func(node)

        return e.source(), e.py_to_c

    def _emit_func(self, node: ast.FunctionDef):
        e = self.emitter
        args = ", ".join(f"int {a.arg}" for a in node.args.args)
        e.emit(f"int {node.name}({args}) {{", node.lineno)
        e.indent()
        saved = self._declared.copy()
        self._declared = set(a.arg for a in node.args.args)
        self._in_func = True
        for child in node.body:
            self.visit(child)
        self._in_func = False
        self._declared = saved
        e.emit('return 0;', node.end_lineno)
        e.dedent()
        e.emit('}')
        e.emit('')

    def visit_Assign(self, node: ast.Assign):
        e = self.emitter
        for target in node.targets:
            if not isinstance(target, ast.Name):
                raise TranspileError(f"Line {node.lineno}: only simple variable assignment supported")
            name = target.id
            val = self._expr(node.value)
            if name not in self._declared:
                ctype = _type_for(node.value)
                e.emit(f"{ctype} {name} = {val};", node.lineno)
                self._declared.add(name)
            else:
                e.emit(f"{name} = {val};", node.lineno)

    def visit_AugAssign(self, node: ast.AugAssign):
        e = self.emitter
        name = node.target.id if isinstance(node.target, ast.Name) else "?"
        op = {ast.Add: "+=", ast.Sub: "-=", ast.Mult: "*=", ast.Div: "/="}.get(type(node.op), "+=")
        val = self._expr(node.value)
        e.emit(f"{name} {op} {val};", node.lineno)

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.Call):
            self._emit_call(node.value, node.lineno)
        # ignore bare expressions otherwise

    def _emit_call(self, node: ast.Call, py_line: int):
        e = self.emitter
        if isinstance(node.func, ast.Name) and node.func.id == "print":
            args = node.args
            if not args:
                e.emit('printf("\\n");', py_line)
                return
            # Build a format string
            fmt_parts = []
            c_args = []
            for a in args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    fmt_parts.append(a.value.replace('"', '\\"'))
                elif isinstance(a, ast.Constant) and isinstance(a.value, float):
                    fmt_parts.append("%f")
                    c_args.append(self._expr(a))
                else:
                    fmt_parts.append("%d")
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
        if not isinstance(node.iter, ast.Call) or not isinstance(node.iter.func, ast.Name):
            raise TranspileError(f"Line {node.lineno}: only 'for x in range(...)' loops supported")
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
                # re-emit as else-if inline
                elif_node = node.orelse[0]
                cond2 = self._expr(elif_node.test)
                # patch last line
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

    def visit_Pass(self, node: ast.Pass):
        self.emitter.emit("/* pass */", node.lineno)

    def visit_Break(self, node: ast.Break):
        self.emitter.emit("break;", node.lineno)

    def visit_Continue(self, node: ast.Continue):
        self.emitter.emit("continue;", node.lineno)

    def generic_visit(self, node: ast.AST):
        raise TranspileError(f"Unsupported Python construct: {type(node).__name__} at line {getattr(node, 'lineno', '?')}")

    def _expr(self, node: ast.expr) -> str:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                escaped = node.value.replace('"', '\\"')
                return f'"{escaped}"'
            if isinstance(node.value, bool):
                return "1" if node.value else "0"
            return str(node.value)
        if isinstance(node, ast.Name):
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
            func_name = self._expr(node.func)
            args = ", ".join(self._expr(a) for a in node.args)
            return f"{func_name}({args})"
        if isinstance(node, ast.Attribute):
            return f"{self._expr(node.value)}.{node.attr}"
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
