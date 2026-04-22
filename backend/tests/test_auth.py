import pytest

pytestmark = pytest.mark.asyncio


async def test_register_success(client):
    r = await client.post("/auth/register", json={"email": "a@test.com", "password": "secret123"})
    assert r.status_code == 201
    assert "access_token" in r.json()


async def test_register_duplicate_email(client):
    payload = {"email": "dup@test.com", "password": "secret123"}
    await client.post("/auth/register", json=payload)
    r = await client.post("/auth/register", json=payload)
    assert r.status_code == 409


async def test_login_success(client):
    await client.post("/auth/register", json={"email": "b@test.com", "password": "mypass"})
    r = await client.post("/auth/login", json={"email": "b@test.com", "password": "mypass"})
    assert r.status_code == 200
    assert "access_token" in r.json()


async def test_login_wrong_password(client):
    await client.post("/auth/register", json={"email": "c@test.com", "password": "correct"})
    r = await client.post("/auth/login", json={"email": "c@test.com", "password": "wrong"})
    assert r.status_code == 401


async def test_login_unknown_email(client):
    r = await client.post("/auth/login", json={"email": "nobody@test.com", "password": "x"})
    assert r.status_code == 401


async def test_password_not_stored_plain(client, db_session):
    from app.auth import get_user_by_email
    await client.post("/auth/register", json={"email": "d@test.com", "password": "plaintext"})
    user = await get_user_by_email(db_session, "d@test.com")
    assert user is not None
    assert user.password_hash != "plaintext"
    assert user.password_hash.startswith("$2")  # bcrypt prefix
