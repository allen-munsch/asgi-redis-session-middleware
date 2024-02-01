import asyncio
import json
import pickle
from sqlite3 import IntegrityError
import sys
import uuid
from base64 import b64decode, b64encode
from typing import Any, Union
from itsdangerous import BadSignature
import itsdangerous
import sqlalchemy
from starlette.datastructures import Secret, MutableHeaders
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import HTTPConnection
from starlette.authentication import BaseUser, UnauthenticatedUser
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from redis.asyncio import Redis as AsyncRedis
from starlette.authentication import (
    AuthCredentials, AuthenticationBackend, AuthenticationError, SimpleUser
)
import base64
import binascii
from vertexai_loaders.config import get_redis_config
from vertexai_loaders.db.session import get_db
from vertexai_loaders.services.user import create_user, get_user_selected_history
import logging

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

log = logging.getLogger(__name__)


class RedisSessionStorage:
    def __init__(self, redis_url: str, expire_time: int = 3600):
        self.client = AsyncRedis.from_url(redis_url)
        self.expire_time = expire_time

    async def __getitem__(self, key: str):
        item = await self.client.get(key)
        if item:
            # WARNING: if a value stored came from a user, this could be a problem
            return pickle.loads(await self.client.get(key))
        return item

    async def __setitem__(self, key: str, value: Any):
        '''
        # WARNING: data stored in redis, none of it should come from user values
        # if it is, they can get remote execution from the pickle loading
        # pickle.loads(b'{my: "value", "hax": exec(maliciouscode)}')
        '''
        return await self.client.set(key, pickle.dumps(value), ex=self.expire_time)

    async def __delitem__(self, key: str):
        await self.client.delete(key)

    async def get_session_id(self) -> str:
        while True:
            session_id = uuid.uuid4().hex
            exists = await self.client.exists(session_id)
            if not exists:
                break
        return session_id


class RedisSessionMiddleware(SessionMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        secret_key: Union[str, Secret],
        session_cookie: str = "session",
        max_age: int = 14 * 24 * 60 * 60,  # 14 days in seconds
        path: str = "/",
        same_site: Literal["lax", "strict", "none"] = "lax",
        https_only: bool = False,
        api=None,
        redis_url: str = None,
        redis_expire_time: int = 60 * 30,
    ):
        super().__init__(app, secret_key, session_cookie, max_age, path, same_site, https_only)
        self.redis = RedisSessionStorage(redis_url, expire_time=redis_expire_time)
        self.api = api
        if self.api:
            @self.api.on_event("shutdown")
            async def shutdown():
                await self.redis.client.close()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True
        redis_key = ""
        if self.session_cookie in connection.cookies:
            data = connection.cookies[self.session_cookie].encode("utf-8")
            try:
                data = self.signer.unsign(data, max_age=self.max_age)
                
                session_data = await self.redis.__getitem__(data)
                if session_data is not None:
                    scope["session"] = json.loads(b64decode(session_data))
                    initial_session_was_empty = False
            except (BadSignature, json.JSONDecodeError):
                scope["session"] = {}
        else:
            scope["session"] = {}


        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and scope.get("session"):
                if scope.get('session') is not None:
                    if scope["session"]:
                        # We have session data to persist.
                        data = b64encode(json.dumps(scope["session"]).encode("utf-8"))
                        data = self.signer.sign(data)
                        headers = MutableHeaders(scope=message)
                        await self.redis.__setitem__(data, scope['user'].__dict__)
                        header_value = "{session_cookie}={data}; path={path}; {max_age}{security_flags}".format(  # noqa E501
                            session_cookie=self.session_cookie,
                            data=data.decode("utf-8"),
                            path=self.path,
                            max_age=f"Max-Age={self.max_age}; " if self.max_age else "",
                            security_flags=self.security_flags,
                        )
                        headers.append("Set-Cookie", header_value)
                    elif not initial_session_was_empty:
                        # The session has been cleared.
                        await self.redis.__delitem__(data)
                        headers = MutableHeaders(scope=message)
                        header_value = "{session_cookie}={data}; path={path}; {expires}{security_flags}".format(  # noqa E501
                            session_cookie=self.session_cookie,
                            data="null",
                            path=self.path,
                            expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
                            security_flags=self.security_flags,
                        )
                        headers.append("Set-Cookie", header_value)

            await send(message)
        if scope.get('session') is None:
            scope['session'] = {}
        await self.app(scope, receive, send_wrapper)

