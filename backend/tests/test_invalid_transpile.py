"""
API-level integration tests for /compile → 422 on unsupported Python constructs.

Each test exercises a distinct transpiler rejection path. No mocking — the real
transpiler and real gcc run so these are true end-to-end integration tests.

Response shape on 422: {"detail": "<message string>"}

Already covered in test_compile.py (do not duplicate):
  - import os  → 422
  - >200 lines  → 422
  - >10 000 chars → 422
"""
import pytest

pytestmark = pytest.mark.asyncio


# ── Unsupported statement types (generic_visit) ────────────────────────────────

async def test_lambda_raises_422(client):
    r = await client.post("/compile", json={"code": "f = lambda x: x + 1"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_list_comprehension_raises_422(client):
    r = await client.post("/compile", json={"code": "squares = [x * x for x in range(5)]"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_dict_comprehension_raises_422(client):
    r = await client.post("/compile", json={"code": "d = {x: x * 2 for x in range(3)}"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_set_comprehension_raises_422(client):
    r = await client.post("/compile", json={"code": "s = {x for x in range(3)}"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_try_except_raises_422(client):
    code = "try:\n    x = 1\nexcept Exception:\n    x = 0\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_with_statement_raises_422(client):
    code = "with open('file.txt') as f:\n    x = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_yield_raises_422(client):
    code = "def gen():\n    yield 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_assert_statement_raises_422(client):
    r = await client.post("/compile", json={"code": "assert 1 == 1"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_raise_statement_raises_422(client):
    r = await client.post("/compile", json={"code": "raise ValueError('oops')"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_del_statement_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 1\ndel x\n"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_global_statement_raises_422(client):
    code = "def foo():\n    global x\n    x = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_nonlocal_statement_raises_422(client):
    code = "def outer():\n    x = 0\n    def inner():\n        nonlocal x\n        x = 1\n"
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_fstring_raises_422(client):
    r = await client.post("/compile", json={"code": 'name = "world"\nx = f"hello {name}"'})
    assert r.status_code == 422
    assert "detail" in r.json()


# ── Non-range for-loop (visit_For guard) ──────────────────────────────────────

async def test_for_over_list_literal_raises_422(client):
    r = await client.post("/compile", json={"code": "for x in [1, 2, 3]:\n    y = x\n"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "range" in body["detail"].lower()


async def test_for_over_variable_raises_422(client):
    # "items" is a plain Name — the for-loop guard fires: "only range() iterator supported"
    r = await client.post("/compile", json={"code": "for x in items:\n    y = x\n"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "range" in body["detail"].lower()


# ── Tuple-unpacking assignment (visit_Assign guard) ───────────────────────────

async def test_tuple_unpack_raises_422(client):
    r = await client.post("/compile", json={"code": "a, b = 1, 2"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "assignment" in body["detail"].lower()


async def test_multi_target_unpack_raises_422(client):
    r = await client.post("/compile", json={"code": "x, y, z = 1, 2, 3"})
    assert r.status_code == 422
    assert "detail" in r.json()


# ── Unsupported binary operators (_expr BinOp guard) ─────────────────────────

async def test_left_shift_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 1 << 2"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    # The error message names the operator type
    assert "LShift" in body["detail"] or "operator" in body["detail"].lower()


async def test_right_shift_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 8 >> 1"})
    assert r.status_code == 422
    assert "detail" in r.json()


async def test_bitwise_and_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 5 & 3"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "BitAnd" in body["detail"] or "operator" in body["detail"].lower()


async def test_bitwise_or_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 5 | 3"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "BitOr" in body["detail"] or "operator" in body["detail"].lower()


async def test_bitwise_xor_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 5 ^ 3"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "BitXor" in body["detail"] or "operator" in body["detail"].lower()


async def test_power_operator_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 5 ** 2"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "Pow" in body["detail"] or "operator" in body["detail"].lower()


# ── Syntax errors (SyntaxError → TranspileError) ─────────────────────────────

async def test_if_missing_colon_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 1\nif x > 0\n    y = 1\n"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "syntax" in body["detail"].lower()


async def test_def_missing_parens_raises_422(client):
    r = await client.post("/compile", json={"code": "def foo\n    x = 1\n"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "syntax" in body["detail"].lower()


async def test_mismatched_parens_raises_422(client):
    r = await client.post("/compile", json={"code": "x = ((1 + 2\n"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "syntax" in body["detail"].lower()


async def test_gibberish_raises_422(client):
    r = await client.post("/compile", json={"code": "@@@"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "syntax" in body["detail"].lower()


async def test_incomplete_expression_raises_422(client):
    r = await client.post("/compile", json={"code": "x = 1 +"})
    assert r.status_code == 422
    body = r.json()
    assert "detail" in body
    assert "syntax" in body["detail"].lower()


# ── Detail message is a non-empty string ─────────────────────────────────────

async def test_422_detail_is_nonempty_string_for_lambda(client):
    r = await client.post("/compile", json={"code": "f = lambda x: x"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert isinstance(detail, str)
    assert len(detail) > 0


async def test_422_detail_is_nonempty_string_for_syntax_error(client):
    r = await client.post("/compile", json={"code": "@@@"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert isinstance(detail, str)
    assert len(detail) > 0


async def test_422_detail_is_nonempty_string_for_unsupported_operator(client):
    r = await client.post("/compile", json={"code": "x = 2 ** 10"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert isinstance(detail, str)
    assert len(detail) > 0
