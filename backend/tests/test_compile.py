import pytest
from unittest.mock import AsyncMock, patch

pytestmark = pytest.mark.asyncio


async def test_compile_requires_auth(client):
    r = await client.post("/compile", json={"code": "x = 1"})
    assert r.status_code == 403


async def test_compile_with_auth(client):
    await client.post("/auth/register", json={"email": "e@test.com", "password": "pass"})
    login = await client.post("/auth/login", json={"email": "e@test.com", "password": "pass"})
    token = login.json()["access_token"]

    fake_result = {
        "python_lines": ["x = 1"],
        "c_code": "int main() { int x = 1; return 0; }",
        "c_lines": ["int main() { int x = 1; return 0; }"],
        "asm_code": "movl $1, -4(%ebp)",
        "asm_lines": ["movl $1, -4(%ebp)"],
        "line_map": {1: {"c_lines": [1], "asm_lines": [1], "color": "#FF6B6B"}},
    }

    with patch("app.main.compile_python", new=AsyncMock(return_value=fake_result)):
        r = await client.post(
            "/compile",
            json={"code": "x = 1"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200
    body = r.json()
    assert "line_map" in body
    assert "c_code" in body
    assert "asm_code" in body


async def test_compile_too_many_lines(client):
    await client.post("/auth/register", json={"email": "f@test.com", "password": "pass"})
    login = await client.post("/auth/login", json={"email": "f@test.com", "password": "pass"})
    token = login.json()["access_token"]
    big_code = "\n".join(["x = 1"] * 300)
    r = await client.post(
        "/compile",
        json={"code": big_code},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


async def test_compile_invalid_python(client):
    await client.post("/auth/register", json={"email": "g@test.com", "password": "pass"})
    login = await client.post("/auth/login", json={"email": "g@test.com", "password": "pass"})
    token = login.json()["access_token"]
    r = await client.post(
        "/compile",
        json={"code": "import os\nos.system('ls')"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422
