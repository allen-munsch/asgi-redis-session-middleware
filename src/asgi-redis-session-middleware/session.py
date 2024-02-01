from typing import Any, Literal
from uuid import uuid4
from fastapi.requests import HTTPConnection
from redis import Redis
from base64 import b64decode, b64encode
import typing
import json
from fastapi import FastAPI
from starlette.datastructures import Secret
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp
from redis.asyncio import Redis
import json
import typing
from base64 import b64decode, b64encode

from itsdangerous.exc import BadSignature

from starlette.datastructures import MutableHeaders, Secret
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RedisSessionStorage:
    def __init__(self, redis_url: str, expire_time: int = 3600):
        self.client = Redis.from_url(redis_url)
        self.expire_time = expire_time

    async def __getitem__(self, key: str):
        return await self.client.get(key)

    async def __setitem__(self, key: str, value: Any):
        await self.client.set(
            key,
            value,
            ex=self.expire_time,
        )

    async def __delitem__(self, key: str):
        await self.client.delete(key)

    async def get_session_id(self) -> str:
        while True:
            session_id = uuid4().hex
            exists = await self.client.exists(session_id)
            if not exists:
                break
        return session_id


class RedisSessionMiddleware(SessionMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        secret_key: typing.Union[str, Secret],
        session_cookie: str = "session",
        max_age: typing.Optional[int] = 14 * 24 * 60 * 60,  # 14 days, in seconds
        path: str = "/",
        same_site: Literal["lax", "strict", "none"] = "lax",
        https_only: bool = False,
        api: FastAPI = None,
        redis_url: str = None,
        redis_expire_time: int = 3600,
    ) -> None:
        super().__init__(
            app,
            secret_key,
            session_cookie,
            max_age,
            path,
            same_site,
            https_only,
        )
        self.redis = RedisSessionStorage(redis_url, expire_time=redis_expire_time)

        @api.on_event("shutdown")
        async def shutdown():
            await self.redis.client.aclose()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True
        redis_key = await self.redis.get_session_id()

        if self.session_cookie in connection.cookies:
            data = connection.cookies[self.session_cookie].encode("utf-8")
            try:
                data = self.signer.unsign(data, max_age=self.max_age)
                redis_key = data
                scope["session"] = json.loads(b64decode(
                    await self.redis[redis_key]
                ))
                initial_session_was_empty = False
            except BadSignature:
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                if scope["session"]:
                    # We have session data to persist.
                    redis_val = scope["session"]
                    self.redis[redis_key] = redis_val
                    data = b64encode(json.dumps(redis_val).encode("utf-8"))
                    data = self.signer.sign(data)
                    headers = MutableHeaders(scope=message)
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
                    headers = MutableHeaders(scope=message)
                    header_value = "{session_cookie}={data}; path={path}; {expires}{security_flags}".format(  # noqa E501
                        session_cookie=self.session_cookie,
                        data="null",
                        path=self.path,
                        expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
                        security_flags=self.security_flags,
                    )
                    headers.append("Set-Cookie", header_value)
                    del self.redis[redis_key]

            await send(message)

        await self.app(scope, receive, send_wrapper)
