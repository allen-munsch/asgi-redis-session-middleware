
class RedisUser(BaseUser):
    def __init__(self, username: str, metadata: dict) -> None:
        self.preferred_username = username
        self.metadata = metadata

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.preferred_username
    
    async def selected_history(self) -> int:
        with get_db() as session:
            return await get_user_selected_history(session, self.preferred_username)


redis_storage = RedisSessionStorage(redis_url=get_redis_config())

class SessionAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn):
        try:
            loggedin = await redis_storage[conn.cookies.get("session")]
            if loggedin:
                user = RedisUser(loggedin['preferred_username'], loggedin)
                try:
                    with get_db() as session:
                        await create_user(session, user)
                except sqlalchemy.exc.IntegrityError:
                    pass
                return AuthCredentials(["authenticated"]), user
        except Exception as e:
            log.info(f'Failed to get session: {conn.cookies.get("session")}')
            conn.scope['session'] = {}
        return AuthCredentials(["authenticated"]), UnauthenticatedUser()

