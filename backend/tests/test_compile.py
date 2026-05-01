import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.asyncio

# Auth was removed from the /compile endpoint — it is now public.
# Tests no longer register/login; they POST directly to /compile.


async def test_compile_no_auth_required(client):
    # /compile must return 200 without any Authorization header now that
    # the JWT guard was removed from the endpoint.
    with patch("app.main.compile_python", new=AsyncMock(return_value=_fake_result())):
        r = await client.post("/compile", json={"code": "x = 1"})
    assert r.status_code == 200


async def test_compile_returns_expected_fields(client):
    with patch("app.main.compile_python", new=AsyncMock(return_value=_fake_result())):
        r = await client.post("/compile", json={"code": "x = 1"})
    body = r.json()
    assert "line_map" in body
    assert "c_code" in body
    assert "asm_code" in body
    assert "python_lines" in body
    assert "c_lines" in body
    assert "asm_lines" in body


async def test_compile_too_many_lines(client):
    # The transpiler rejects inputs longer than 200 lines — no auth needed.
    big_code = "\n".join(["x = 1"] * 300)
    r = await client.post("/compile", json={"code": big_code})
    assert r.status_code == 422


async def test_compile_invalid_python_construct(client):
    # Unsupported constructs (e.g. import) raise TranspileError → 422.
    r = await client.post("/compile", json={"code": "import os\nos.system('ls')"})
    assert r.status_code == 422


async def test_compile_simple_assignment(client):
    # End-to-end: real transpiler + real gcc — verifies the whole pipeline.
    r = await client.post("/compile", json={"code": "x = 42"})
    assert r.status_code == 200
    body = r.json()
    assert len(body["c_lines"]) > 0
    assert len(body["asm_lines"]) > 0
    # JSON serializes dict keys as strings; the API returns {"1": {...}} not {1: {...}}
    assert "1" in body["line_map"]


async def test_compile_for_loop(client):
    r = await client.post("/compile", json={"code": "for i in range(5):\n    x = i\n"})
    assert r.status_code == 200
    body = r.json()
    # Line map must have entries for both loop lines
    assert len(body["line_map"]) >= 2


async def test_compile_function_def(client):
    r = await client.post("/compile", json={"code": "def add(a, b):\n    return a + b\n"})
    assert r.status_code == 200
    body = r.json()
    assert any("add" in line for line in body["c_lines"])


async def test_compile_empty_code(client):
    # Empty input is valid Python — transpiler emits a bare main().
    r = await client.post("/compile", json={"code": ""})
    assert r.status_code == 200


async def test_compile_oversized_code_rejected(client):
    # 10 001 chars exceeds the character cap.
    huge = "x = 1\n" * 2000
    r = await client.post("/compile", json={"code": huge})
    assert r.status_code == 422


async def test_compile_line_map_colors_are_hex(client):
    r = await client.post("/compile", json={"code": "x = 1\ny = 2\n"})
    assert r.status_code == 200
    for _line, mapping in r.json()["line_map"].items():
        color = mapping["color"]
        assert color.startswith("#"), f"Expected hex color, got: {color}"


async def test_compile_vuln_stack_bof_code(client):
    # Regression: the stack-BOF vuln template from the sidebar must compile.
    code = (
        "def fill_buffer():\n"
        "    buf_size = 8\n"
        "    total_writes = 16\n"
        "    value = 0\n"
        "    i = 0\n"
        "    while i < total_writes:\n"
        "        value += i\n"
        "        if i >= buf_size:\n"
        "            print(value)\n"
        "        i += 1\n"
        "    return value\n"
        "\n"
        "result = fill_buffer()\n"
        "print(result)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200


async def test_compile_vuln_int_overflow_code(client):
    code = (
        "def calc_allocation():\n"
        "    width = 50000\n"
        "    height = 50000\n"
        "    total = width * height\n"
        "    max_int32 = 2147483647\n"
        "    if total > max_int32:\n"
        "        print(total)\n"
        "    else:\n"
        "        print(0)\n"
        "    return total\n"
        "\n"
        "size = calc_allocation()\n"
        "print(size)\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200


async def test_compile_vuln_uninit_var_code(client):
    code = (
        "def compute():\n"
        "    flag = 0\n"
        "    result = 0\n"
        "    if flag > 0:\n"
        "        result = 42\n"
        "    elif flag < 0:\n"
        "        result = -1\n"
        "    print(result)\n"
        "    return result\n"
        "\n"
        "def run():\n"
        "    x = compute()\n"
        "    if x > 0:\n"
        "        print(x)\n"
        "    return x\n"
        "\n"
        "run()\n"
    )
    r = await client.post("/compile", json={"code": code})
    assert r.status_code == 200


# ─── helper ───────────────────────────────────────────────────────────────────

def _fake_result() -> dict:
    return {
        "python_lines": ["x = 1"],
        "c_code": "int main() { int x = 1; return 0; }",
        "c_lines": ["int main() { int x = 1; return 0; }"],
        "asm_code": "movl $1, -4(%ebp)",
        "asm_lines": ["movl $1, -4(%ebp)"],
        "line_map": {1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"}},
    }
