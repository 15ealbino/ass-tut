import pytest

pytestmark = pytest.mark.asyncio

# All passwords are ≥8 chars to satisfy the UserRegister min_length validator.


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
    # Password must be ≥8 chars — "mypass" (6) caused a 422 on register,
    # making the subsequent login return 401 because the user was never created.
    await client.post("/auth/register", json={"email": "b@test.com", "password": "mypassword"})
    r = await client.post("/auth/login", json={"email": "b@test.com", "password": "mypassword"})
    assert r.status_code == 200
    assert "access_token" in r.json()


async def test_login_wrong_password(client):
    await client.post("/auth/register", json={"email": "c@test.com", "password": "correctpass"})
    r = await client.post("/auth/login", json={"email": "c@test.com", "password": "wrongpass"})
    assert r.status_code == 401


async def test_login_unknown_email(client):
    r = await client.post("/auth/login", json={"email": "nobody@test.com", "password": "whatever1"})
    assert r.status_code == 401


async def test_password_not_stored_plain(client, db_session):
    from app.auth import get_user_by_email
    await client.post("/auth/register", json={"email": "d@test.com", "password": "plaintext1"})
    user = await get_user_by_email(db_session, "d@test.com")
    assert user is not None
    assert user.password_hash != "plaintext1"
    # bcrypt hashes always start with $2b$ or $2y$
    assert user.password_hash.startswith("$2")


async def test_register_password_too_short_returns_422(client):
    # Passwords shorter than 8 chars are rejected by the schema before any DB write.
    r = await client.post("/auth/register", json={"email": "short@test.com", "password": "abc"})
    assert r.status_code == 422


async def test_register_invalid_email_format_returns_422(client):
    r = await client.post("/auth/register", json={"email": "not-an-email", "password": "validpass1"})
    assert r.status_code == 422


async def test_login_token_is_string(client):
    await client.post("/auth/register", json={"email": "tok@test.com", "password": "tokentest1"})
    r = await client.post("/auth/login", json={"email": "tok@test.com", "password": "tokentest1"})
    data = r.json()
    assert isinstance(data["access_token"], str)
    assert len(data["access_token"]) > 20
