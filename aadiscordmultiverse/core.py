"""Core functionality of the Discord service not directly related to models."""

import logging
from typing import List, Optional, Tuple

from requests.exceptions import HTTPError

from django.contrib.auth.models import Group, User

from allianceauth.groupmanagement.models import ReservedGroupName
from allianceauth.services.hooks import NameFormatter

from . import __title__
from .app_settings import DISCORD_BOT_TOKEN
from .discord_client import DiscordClient, RolesSet, Role
from .discord_client.exceptions import DiscordClientException
from .utils import LoggerAddTag

logger = LoggerAddTag(logging.getLogger(__name__), __title__)


def create_bot_client(is_rate_limited: bool = True) -> DiscordClient:
    """Create new bot client for accessing the configured Discord server.

    Args:
        is_rate_limited: Set to False to turn off rate limiting (use with care).

    Return:
        Discord client instance
    """
    return DiscordClient(DISCORD_BOT_TOKEN, is_rate_limited=is_rate_limited)


def calculate_roles_for_user(
    user: User,
    client: DiscordClient,
    discord_uid: int,
    guild_id: int,
    groups,
    state_name: str = None
) -> Tuple[RolesSet, Optional[bool]]:
    """Calculate current Discord roles for an Auth user.

    Takes into account reserved groups and existing managed roles (e.g. nitro).

    Returns:
        - Discord roles, changed flag:
            - True when roles have changed,
            - False when they have not changed,
            - None if user is not a member of the guild
    """
    roles_calculated = client.match_or_create_roles_from_names_2(
        guild_id=guild_id,
        role_names=groups,
    )
    logger.debug("Calculated roles for user %s: %s", user, roles_calculated.ids())
    roles_current = client.guild_member_roles(
        guild_id=guild_id, user_id=discord_uid
    )
    if roles_current is None:
        logger.debug("User %s is not a member of the guild.", user)
        return roles_calculated, None
    logger.debug("Current roles user %s: %s", user, roles_current.ids())
    reserved_role_names = ReservedGroupName.objects.values_list("name", flat=True)
    roles_reserved = roles_current.subset(role_names=reserved_role_names)
    roles_managed = roles_current.subset(managed_only=True)
    roles_persistent = roles_managed.union(roles_reserved)
    if roles_calculated == roles_current.difference(roles_persistent):
        return roles_calculated, False
    return roles_calculated.union(roles_persistent), True


def user_formatted_nick(user: User) -> Optional[str]:
    """Name of the given user's main character with name formatting applied.

    Returns:
        Name or ``None`` if user has no main.
    """
    from .auth_hooks import DiscordService

    if user.profile.main_character:
        return NameFormatter(DiscordService(), user).format_name()
    return None


def group_to_role(group: Group, guild_id: int) -> Optional[Role]:
    """Fetch the Discord role matching the given Django group by name.

    Returns:
        Discord role or None if no matching role exist
    """
    return default_bot_client.match_role_from_name(
        guild_id=guild_id, role_name=group.name
    )


def server_name(guild_id: int, use_cache: bool = True) -> str:
    """Fetches the name of the current Discord server.

    Args:
        use_cache: When set False will force an API call to get the server name

    Returns:
        Server name or an empty string if the name could not be retrieved
    """
    try:
        server_name = default_bot_client.guild_name(
            guild_id=guild_id, use_cache=use_cache
        )
    except (HTTPError, DiscordClientException):
        server_name = ""
    except Exception:
        logger.warning(
            "Unexpected error when trying to retrieve the server name from Discord",
            exc_info=True,
        )
        server_name = ""
    return server_name


# Default bot client to be used by modules of this package
default_bot_client = create_bot_client()
