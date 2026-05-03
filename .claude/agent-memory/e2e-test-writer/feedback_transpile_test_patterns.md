---
name: Transpiler rejection test patterns
description: Gotchas and confirmed patterns for testing /compile 422 rejections in this codebase
type: feedback
---

Use `for x in items:` (bare Name) not `for x in some_list:` preceded by a list-literal assignment when testing the non-range for-loop guard. If you write `items = [1, 2]\nfor x in items:`, the `[1, 2]` list literal hits `_expr` and raises `"Unsupported expression: List"` before the for-loop guard fires — so the detail won't contain "range". Using a bare, undeclared name as the iterator hits `visit_For` directly.

**Why:** The `_expr` method is called on the iterator value before `visit_For` checks whether it's a `range()` call. List literals resolve through `_expr` → raise on `ast.List` first.

**How to apply:** When writing tests for the `for x in non_range` rejection path, use an undeclared identifier (e.g. `for x in items:\n    y = x`) rather than pre-assigning a list. The former hits `visit_For`'s range guard; the latter hits `_expr`'s List guard first.
