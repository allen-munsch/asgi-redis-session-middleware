import os
from starlette.authentication import BaseUser, UnauthenticatedUser
from starlette.authentication import (
    AuthCredentials, AuthenticationBackend
)
import logging

from asgi_redis_session_middleware.session import RedisSessionStorage

log = logging.getLogger(__name__)

class RedisUser(BaseUser):
    def __init__(self, metadata: dict) -> None:
        self.metadata = metadata

    @property
    def is_authenticated(self) -> bool:
        return True

redis_uri = os.environ.get('REDIS_URI')
assert redis_uri, 'environment variable missing: REDIS_URI'

class SessionAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        redis_storage = RedisSessionStorage(redis_url=redis_uri)
        try:
            loggedin = await redis_storage[conn.cookies.get("session")]
            if loggedin:
                user = RedisUser(loggedin)
                return AuthCredentials(["authenticated"]), user
        except Exception as e:
            log.info(f'Failed to get session: {conn.cookies.get("session")}')
            conn.scope['session'] = {}
        return AuthCredentials(["authenticated"]), UnauthenticatedUser()

