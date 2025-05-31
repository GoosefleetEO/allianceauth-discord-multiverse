from itertools import count

from django.utils.timezone import now

from ..client import DiscordApiStatusCode
from ..models import Guild, GuildMember, Role, User

TEST_GUILD_ID = 123456789012345678
TEST_GUILD_NAME = "Test Guild"
TEST_USER_ID = 198765432012345678
TEST_USER_NAME = "Peter Parker"
TEST_USER_DISCRIMINATOR = "1234"
TEST_BOT_TOKEN = "abcdefhijlkmnopqastzvwxyz1234567890ABCDEFGHOJKLMNOPQRSTUVWXY"
TEST_ROLE_ID = 654321012345678912


def create_discord_role_object(id: int, name: str, managed: bool = False) -> dict:
    return {"id": str(int(id)), "name": str(name), "managed": bool(managed)}


def create_matched_role(role, created=False) -> tuple:
    return role, created


def create_discord_user_object(**kwargs):
    params = {
        "id": TEST_USER_ID,
        "username": TEST_USER_NAME,
        "discriminator": TEST_USER_DISCRIMINATOR,
    }
    params.update(kwargs)
    params["id"] = str(int(params["id"]))
    return params


def create_discord_guild_member_object(user=None, **kwargs):
    user_params = {}
    if user:
        user_params["user"] = user
    params = {
        "user": create_discord_user_object(**user_params),
        "roles": [],
        "joined_at": now().isoformat(),
        "deaf": False,
        "mute": False,
    }
    params.update(kwargs)
    params["roles"] = [str(int(obj)) for obj in params["roles"]]
    return params


def create_discord_error_response(code: int) -> dict:
    return {"code": int(code)}


def create_discord_error_response_unknown_member() -> dict:
    return create_discord_error_response(DiscordApiStatusCode.UNKNOWN_MEMBER.value)


def create_discord_guild_object(**kwargs):
    params = {"id": TEST_GUILD_ID, "name": TEST_GUILD_NAME, "roles": []}
    params.update(kwargs)
    params["id"] = str(int(params["id"]))
    return params


def create_user(**kwargs):
    params = {
        "id": TEST_USER_ID,
        "username": TEST_USER_NAME,
        "discriminator": TEST_USER_DISCRIMINATOR,
    }
    params.update(kwargs)
    return User(**params)


def create_guild(**kwargs):
    params = {"id": TEST_GUILD_ID, "name": TEST_GUILD_NAME, "roles": []}
    params.update(kwargs)
    return Guild(**params)


def create_guild_member(**kwargs):
    params = {"user": create_user(), "roles": []}
    params.update(kwargs)
    return GuildMember(**params)


def create_role(**kwargs) -> dict:
    params = {"managed": False}
    params.update(kwargs)
    if "id" not in params:
        params["id"] = next_number("role")
    if "name" not in params:
        params["name"] = f"Test Role #{params['id']}"
    return Role(**params)


def next_number(key: str = None) -> int:
    """Calculate the next number in a persistent sequence."""
    if key is None:
        key = "_general"
    try:
        return next_number._counter[key].__next__()
    except AttributeError:
        next_number._counter = dict()
    except KeyError:
        pass
    next_number._counter[key] = count(start=1)
    return next_number._counter[key].__next__()
