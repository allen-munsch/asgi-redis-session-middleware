from unittest.mock import AsyncMock
from starlette.authentication import UnauthenticatedUser
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock
from asgi_redis_session_middleware.backend import RedisUser, SessionAuthBackend, redis_uri
from httpx import Cookies
import pytest
import pytest_asyncio
from unittest import TestCase
from starlette.applications import Starlette

from asgi_redis_session_middleware.session import RedisSessionStorage

@pytest_asyncio.fixture
async def client():
    from starlette.testclient import TestClient

    client = TestClient(Starlette())
    yield client
    client.cookies.clear()


@pytest.mark.asyncio
async def test_session_auth_backend_not_logged_in(client):
    # You'll need to set up your Redis storage for testing, which might include mocking
    backend = SessionAuthBackend()
    conn = AsyncMock()
    conn.cookies = client.cookies
    # Attempt to authenticate using the backend
    credentials, user = await backend.authenticate(conn)
    assert credentials.scopes == ["authenticated"]
    assert isinstance(user, UnauthenticatedUser)
    assert not user.is_authenticated

@pytest_asyncio.fixture
async def client():
    from starlette.testclient import TestClient

    client = TestClient(Starlette())
    yield client
    client.cookies.clear()


@pytest.mark.asyncio
async def test_session_auth_backend_logged_in(client):
    redis_storage = RedisSessionStorage(redis_url=redis_uri)

    backend = SessionAuthBackend()
    key = "testkey"
    data = {'id': {'some': 'info'}}
    ok = await redis_storage.__setitem__(key, data)
    assert ok
    from_redis = await redis_storage[key]
    TestCase().assertDictEqual(data, from_redis)
    mock_conn = AsyncMock()
    mock_conn.cookies = Cookies()
    mock_conn.cookies.set("session", key)
    # Attempt to authenticate using the backend
    assert mock_conn.cookies.get("session") == key
    credentials, user = await backend.authenticate(mock_conn)
    assert credentials.scopes == ["authenticated"]
    assert isinstance(user, RedisUser), f"expected RedisUser got: {user}"
    assert user.is_authenticated is True

