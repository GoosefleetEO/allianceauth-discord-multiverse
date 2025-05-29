"""Client for interacting with the Discord API."""

import json
import logging
from enum import IntEnum
from hashlib import md5
from http import HTTPStatus
from time import sleep
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin
from uuid import uuid1

import requests
from requests.exceptions import HTTPError
from redis import Redis

from allianceauth.utils.cache import get_redis_client

from allianceauth import __title__ as AUTH_TITLE
from allianceauth import __url__, __version__

from .. import __title__
from allianceauth.services.modules.discord.utils import LoggerAddTag
from .app_settings import (
    DISCORD_API_BASE_URL,
    DISCORD_API_TIMEOUT_CONNECT,
    DISCORD_API_TIMEOUT_READ,
    DISCORD_DISABLE_ROLE_CREATION,
    DISCORD_GUILD_NAME_CACHE_MAX_AGE,
    DISCORD_ROLES_CACHE_MAX_AGE,
)
from .exceptions import DiscordRateLimitExhausted, DiscordTooManyRequestsError
from .helpers import RolesSet
from .models import Guild, GuildMember, Role, User

logger = LoggerAddTag(logging.getLogger(__name__), __title__)

# max requests that can be executed until reset
RATE_LIMIT_MAX_REQUESTS = 5

# Time until remaining requests are reset
RATE_LIMIT_RESETS_AFTER = 5000

# Delay used for API backoff in case no info returned from API on 429s
DEFAULT_BACKOFF_DELAY = 5000

# additional duration to compensate for potential clock discrepancies
# with the Discord server
DURATION_CONTINGENCY = 500

# Client will do a blocking wait rather than throwing a backoff exception if the
# time until next reset is below this threshold
WAIT_THRESHOLD = 250

# Minimum wait duration when doing a blocking wait
MINIMUM_BLOCKING_WAIT = 50

# If the rate limit resets soon we will wait it out and then retry to
# either get a remaining request from our cached counter
# or again wait out a short reset time and retry again.
# This could happen several times within a high concurrency situation,
# but must fail after x tries to avoid an infinite loop
RATE_LIMIT_RETRIES = 1000


class DiscordApiStatusCode(IntEnum):
    """Status code returned from the Discord API."""
    UNKNOWN_MEMBER = 10007  #:


class DiscordClient:
    """This class provides a web client for interacting with the Discord API.

    The client has rate limiting that supports concurrency.
    This means it is able to ensure the API rate limit is not violated,
    even when used concurrently, e.g. with multiple parallel celery tasks.

    In addition the client support proper API backoff.

    Synchronization of rate limit infos across multiple processes
    is implemented with Redis and thus requires Redis as Django cache backend.

    The cache is shared across all clients and processes (also using Redis).

    All durations are in milliseconds.

    Most errors from the API will raise a requests.HTTPError.

    Args:
        access_token: Discord access token used to authenticate all calls to the API
        redis: Redis instance to be used.
        is_rate_limited: Set to False to turn off rate limiting (use with care).
            If not specified will try to use the Redis instance
            from the default Django cache backend.

    Raises:
        ValueError: No access token provided
    """
    _KEY_GLOBAL_BACKOFF_UNTIL = 'DISCORD_GLOBAL_BACKOFF_UNTIL'
    _KEY_GLOBAL_RATE_LIMIT_REMAINING = 'DISCORD_GLOBAL_RATE_LIMIT_REMAINING'
    _KEYPREFIX_GUILD_NAME = 'DISCORD_GUILD_NAME'
    _KEYPREFIX_GUILD_ROLES = 'DISCORD_GUILD_ROLES'
    _KEYPREFIX_ROLE_NAME = 'DISCORD_ROLE_NAME'

    def __init__(
        self,
        access_token: str,
        redis: Redis = None,
        is_rate_limited: bool = True
    ) -> None:
        if not access_token:
            raise ValueError('You must provide an access token.')
        self._access_token = str(access_token)
        self._is_rate_limited = bool(is_rate_limited)
        if not redis:
            self._redis = get_redis_client()
            if not isinstance(self._redis, Redis):
                raise RuntimeError(
                    'This class requires a Redis client, but none was provided '
                    'and the default Django cache backend is not Redis either.'
                )
        else:
            self._redis = redis

        lua_1 = """
            if redis.call("exists", KEYS[1]) == 0 then
                redis.call("set", KEYS[1], ARGV[1], 'px', ARGV[2])
            end
            return redis.call("decr", KEYS[1])
        """
        self.__redis_script_decr_or_set = self._redis.register_script(lua_1)

        lua_2 = """
            local current_px = tonumber(redis.call("pttl", KEYS[1]))
            if current_px < tonumber(ARGV[2]) then
                return redis.call("set", KEYS[1], ARGV[1], 'px', ARGV[2])
            else
                return nil
            end
        """
        self.__redis_script_set_longer = self._redis.register_script(lua_2)

    @property
    def access_token(self) -> str:
        """Discord access token."""
        return self._access_token

    @property
    def is_rate_limited(self) -> bool:
        """Wether this instance is rate limited."""
        return self._is_rate_limited

    def __repr__(self):
        return f'{type(self).__name__}(access_token=...{self.access_token[-5:]})'

    def _redis_decr_or_set(self, name: str, value: str, px: int) -> bool:
        """Decrease the key value if it exists and returns the result else set the key.

        Implemented as Lua script to ensure atomicity.
        """
        return self.__redis_script_decr_or_set(
            keys=[str(name)], args=[str(value), int(px)]
        )

    def _redis_set_if_longer(self, name: str, value: str, px: int) -> bool:
        """Like set, but only goes through if either key doesn't exist
        or px would be extended.

        Implemented as Lua script to ensure atomicity.
        """
        return self.__redis_script_set_longer(
            keys=[str(name)], args=[str(value), int(px)]
        )

    # users

    def current_user(self) -> User:
        """Fetch user belonging to the current access_token."""
        authorization = f'Bearer {self.access_token}'
        r = self._api_request(
            method='get', route='users/@me', authorization=authorization
        )
        return User.from_dict(r.json())

    # guild

    def guild_infos(self, guild_id: int) -> Guild:
        """Fetch all basic infos about this guild.

        Args:
            guild_id: Discord ID of the guild
        """
        route = f"guilds/{guild_id}"
        r = self._api_request(method='get', route=route)
        return Guild.from_dict(r.json())

    def guild_name(self, guild_id: int, use_cache: bool = True) -> str:
        """Fetch the name of this guild (cached).

        Args:
            guild_id: Discord ID of the guild
            use_cache: When set to False will force an API call to get the server name

        Returns:
            Name of the server or an empty string if something went wrong.
        """
        key_name = self._guild_name_cache_key(guild_id)
        if use_cache:
            guild_name = self._redis_decode(self._redis.get(key_name))
        else:
            guild_name = ""
        if not guild_name:
            try:
                guild = self.guild_infos(guild_id)
            except HTTPError:
                guild_name = ""
            else:
                guild_name = guild.name
                self._redis.set(
                    name=key_name, value=guild_name, ex=DISCORD_GUILD_NAME_CACHE_MAX_AGE
                )
        return guild_name

    @classmethod
    def _guild_name_cache_key(cls, guild_id: int) -> str:
        """Construct key for accessing role given by name in the role cache.

        Args:
            guild_id: Discord ID of the guild
        """
        gen_key = DiscordClient._generate_hash(f'{guild_id}')
        return f'{cls._KEYPREFIX_GUILD_NAME}__{gen_key}'

    # guild roles

    def guild_roles(self, guild_id: int, use_cache: bool = True) -> Set[Role]:
        """Fetch all roles for this guild.

        Args:
            guild_id: Discord ID of the guild
            use_cache: If is set to False it will always hit the API to retrieve
                fresh data and update the cache.

        Returns:
        """
        cache_key = self._guild_roles_cache_key(guild_id)
        roles = None
        if use_cache:
            roles_raw = self._redis.get(name=cache_key)
            if roles_raw:
                logger.debug('Returning roles for guild %s from cache', guild_id)
                roles = json.loads(self._redis_decode(roles_raw))
            logger.debug('No roles for guild %s in cache', guild_id)
        if roles is None:
            route = f"guilds/{guild_id}/roles"
            r = self._api_request(method='get', route=route)
            roles = r.json()
            if not roles or not isinstance(roles, list):
                raise RuntimeError(
                    f"Unexpected response when fetching roles from API: {roles}"
                )
            self._redis.set(
                name=cache_key,
                value=json.dumps(roles),
                ex=DISCORD_ROLES_CACHE_MAX_AGE
            )
        return {Role.from_dict(role) for role in roles}

    def create_guild_role(
        self, guild_id: int, role_name: str, **kwargs
    ) -> Optional[Role]:
        """Create a new guild role with the given name.

        See official documentation for additional optional parameters.

        Note that Discord allows the creation of multiple roles with the same name,
        so to avoid duplicates it's important to check existing roles
        before creating new one

        Args:
            guild_id: Discord ID of the guild
            role_name: Name of new role to create

        Returns:
            new role on success
        """
        route = f"guilds/{guild_id}/roles"
        data = {'name': Role.sanitize_name(role_name)}
        data.update(kwargs)
        r = self._api_request(method='post', route=route, data=data)
        role = r.json()
        if role:
            self._invalidate_guild_roles_cache(guild_id)
            return Role.from_dict(role)
        return None

    def delete_guild_role(self, guild_id: int, role_id: int) -> bool:
        """Delete a guild role."""
        route = f"guilds/{guild_id}/roles/{role_id}"
        r = self._api_request(method='delete', route=route)
        if r.status_code == 204:
            self._invalidate_guild_roles_cache(guild_id)
            return True
        return False

    def _invalidate_guild_roles_cache(self, guild_id: int) -> None:
        cache_key = self._guild_roles_cache_key(guild_id)
        self._redis.delete(cache_key)
        logger.debug('Guild roles cache invalidated')

    @classmethod
    def _guild_roles_cache_key(cls, guild_id: int) -> str:
        """Construct key for accessing cached roles for a guild.

        Args:
            guild_id: Discord ID of the guild
        """
        gen_key = cls._generate_hash(f'{guild_id}')
        return f'{cls._KEYPREFIX_GUILD_ROLES}__{gen_key}'

    def match_role_from_name(self, guild_id: int, role_name: str) -> Optional[Role]:
        """Fetch Discord role matching the given name (cached).

        Args:
            guild_id: Discord ID of the guild
            role_name: Name of role

        Returns:
            Matching role or None if no match is found
        """
        guild_roles = RolesSet(self.guild_roles(guild_id))
        return guild_roles.role_by_name(role_name)

    def match_or_create_roles_from_names(
        self, guild_id: int, role_names: Iterable[str]
    ) -> List[Tuple[Role, bool]]:
        """Fetch or create Discord roles matching the given names (cached).

        Will try to match with existing roles names
        Non-existing roles will be created, then created flag will be True

        Args:
            guild_id: ID of guild
            role_names: list of name strings each defining a role

        Returns:
            List of tuple of Role and created flag
        """
        roles = list()
        guild_roles = RolesSet(self.guild_roles(guild_id))
        role_names_cleaned = {Role.sanitize_name(name) for name in role_names}
        for role_name in role_names_cleaned:
            role, created = self.match_or_create_role_from_name(
                guild_id=guild_id, role_name=role_name, guild_roles=guild_roles
            )
            if role:
                roles.append((role, created))
            if created:
                guild_roles = guild_roles.union(RolesSet([role]))
        return roles

    def match_or_create_role_from_name(
        self, guild_id: int, role_name: str, guild_roles: RolesSet = None
    ) -> Tuple[Role, bool]:
        """Fetch or create Discord role matching the given name.

        Will try to match with existing roles names
        Non-existing roles will be created, then created flag will be True

        Args:
            guild_id: ID of guild
            role_name: strings defining name of a role
            guild_roles: All known guild roles as RolesSet object.
                Helps to void redundant lookups of guild roles
                when this method is used multiple times.

        Returns:
            Tuple of Role and created flag
        """
        if not isinstance(role_name, str):
            raise TypeError('role_name must be of type string')

        created = False
        if guild_roles is None:
            guild_roles = RolesSet(self.guild_roles(guild_id))
        role = guild_roles.role_by_name(role_name)
        if not role:
            if not DISCORD_DISABLE_ROLE_CREATION:
                logger.debug('Need to create missing role: %s', role_name)
                role = self.create_guild_role(guild_id, role_name)
                created = True
            else:
                role = None
        return role, created

    def match_or_create_roles_from_names_2(
        self, guild_id: int, role_names: Iterable[str]
    ) -> RolesSet:
        """Fetch or create Discord role matching the given name.

        Wrapper for ``match_or_create_role_from_name()``

        Returns:
            Roles as RolesSet object.
        """
        return RolesSet.create_from_matched_roles(
            self.match_or_create_roles_from_names(
                guild_id=guild_id, role_names=role_names
            )
        )

    # guild members

    def add_guild_member(
        self,
        guild_id: int,
        user_id: int,
        access_token: str,
        role_ids: list = None,
        nick: str = None
    ) -> Optional[bool]:
        """Adds a user to the guild.

        Returns:
            - True when a new user was added
            - None if the user already existed
            - False when something went wrong or raises exception
        """
        route = f"guilds/{guild_id}/members/{user_id}"
        data = {
            'access_token': str(access_token)
        }
        if role_ids:
            data['roles'] = self._sanitize_role_ids(role_ids)
        if nick:
            data['nick'] = GuildMember.sanitize_nick(nick)
        r = self._api_request(method='put', route=route, data=data)
        r.raise_for_status()
        if r.status_code == 201:
            return True
        elif r.status_code == 204:
            return None
        return False

    def guild_member(self, guild_id: int, user_id: int) -> Optional[GuildMember]:
        """Fetch info for a guild member.

        Args:
            guild_id: Discord ID of the guild
            user_id: Discord ID of the user

        Returns:
            guild member or ``None`` if the user is not a member of the guild
        """
        route = f'guilds/{guild_id}/members/{user_id}'
        r = self._api_request(method='get', route=route, raise_for_status=False)
        if self._is_member_unknown_error(r):
            logger.warning("Discord user ID %s could not be found on server.", user_id)
            return None
        r.raise_for_status()
        return GuildMember.from_dict(r.json())

    def modify_guild_member(
        self, guild_id: int, user_id: int, role_ids: List[int] = None, nick: str = None
    ) -> Optional[bool]:
        """Set properties of a guild member.

        Args:
            guild_id: Discord ID of the guild
            user_id: Discord ID of the user
            roles_id: New list of role IDs (if provided)
            nick: New nickname (if provided)

        Returns
            - True when successful
            - None if user is not a member of this guild
            - False otherwise
        """
        if not role_ids and not nick:
            raise ValueError('Must specify role_ids or nick')

        if role_ids and not isinstance(role_ids, list):
            raise TypeError('role_ids must be a list type')

        data = dict()
        if role_ids:
            data['roles'] = self._sanitize_role_ids(role_ids)

        if nick:
            data['nick'] = GuildMember.sanitize_nick(nick)

        route = f"guilds/{guild_id}/members/{user_id}"
        r = self._api_request(
            method='patch', route=route, data=data, raise_for_status=False
        )
        if self._is_member_unknown_error(r):
            logger.warning('User ID %s is not a member of this guild', user_id)
            return None
        r.raise_for_status()
        if r.status_code == 204:
            return True
        return False

    def remove_guild_member(self, guild_id: int, user_id: int) -> Optional[bool]:
        """Remove a member from a guild.

        Args:
            guild_id: Discord ID of the guild
            user_id: Discord ID of the user

        Returns:
            - True when successful
            - None if member does not exist
            - False otherwise
        """
        route = f"guilds/{guild_id}/members/{user_id}"
        r = self._api_request(
            method='delete', route=route, raise_for_status=False
        )
        if self._is_member_unknown_error(r):
            logger.warning('User ID %s is not a member of this guild', user_id)
            return None
        r.raise_for_status()
        if r.status_code == 204:
            return True
        return False

    # Guild member roles

    def add_guild_member_role(
        self, guild_id: int, user_id: int, role_id: int
    ) -> Optional[bool]:
        """Adds a role to a guild member

        Returns:
        - True when successful
        - None if member does not exist
        - False otherwise
        """
        route = f"guilds/{guild_id}/members/{user_id}/roles/{role_id}"
        r = self._api_request(method='put', route=route, raise_for_status=False)
        if self._is_member_unknown_error(r):
            logger.warning('User ID %s is not a member of this guild', user_id)
            return None
        r.raise_for_status()
        if r.status_code == 204:
            return True
        return False

    def remove_guild_member_role(
        self, guild_id: int, user_id: int, role_id: int
    ) -> Optional[bool]:
        """Remove a role to a guild member

        Args:
            guild_id: Discord ID of the guild
            user_id: Discord ID of the user
            role_id: Discord ID of role to be removed

        Returns:
            - True when successful
            - None if member does not exist
            - False otherwise
        """
        route = f"guilds/{guild_id}/members/{user_id}/roles/{role_id}"
        r = self._api_request(method='delete', route=route, raise_for_status=False)
        if self._is_member_unknown_error(r):
            logger.warning('User ID %s is not a member of this guild', user_id)
            return None
        r.raise_for_status()
        if r.status_code == 204:
            return True
        return False

    def guild_member_roles(self, guild_id: int, user_id: int) -> Optional[RolesSet]:
        """Fetch the current guild roles of a guild member.

        Args:
        - guild_id: Discord guild ID
        - user_id: Discord user ID

        Returns:
        - Member roles
        - None if user is not a member of the guild
        """
        member_info = self.guild_member(guild_id=guild_id, user_id=user_id)
        if member_info is None:
            return None  # User is no longer a member
        guild_roles = RolesSet(self.guild_roles(guild_id=guild_id))
        logger.debug('Current guild roles: %s', guild_roles.ids())
        _roles = set(member_info.roles)
        if not guild_roles.has_roles(member_info.roles):
            guild_roles = RolesSet(
                self.guild_roles(guild_id=guild_id, use_cache=False)
            )
            if not guild_roles.has_roles(member_info.roles):
                role_ids = set(member_info.roles).difference(guild_roles.ids())
                logger.warning(f'Discord user {user_id} has unknown roles: {role_ids}')
                for _r in role_ids:
                    _roles.remove(_r)
        return guild_roles.subset(_roles)

    @classmethod
    def _is_member_unknown_error(cls, r: requests.Response) -> bool:
        try:
            result = (
                r.status_code == HTTPStatus.NOT_FOUND
                and r.json()['code'] == DiscordApiStatusCode.UNKNOWN_MEMBER
            )
        except (ValueError, KeyError):
            result = False

        return result

    # Internal methods

    def _api_request(
        self,
        method: str,
        route: str,
        data: dict = None,
        authorization: str = None,
        raise_for_status: bool = True
    ) -> requests.Response:
        """Core method for performing all API calls.

        Args:
            method: HTTP method of the request, e.g. "get"
            route: Route in the Discord API, e.g. "users/@me"
            data: Data to be send with the request
            authorization: The authorization string to be used.
                Will use the default bot token if not set.
            raise_for_status: Whether a requests exception is to be raised when not ok

        Returns:
            The raw response from the API
        """
        uid = uuid1().hex

        if not hasattr(requests, method):
            raise ValueError('Invalid method: %s' % method)

        if not authorization:
            authorization = f'Bot {self.access_token}'

        self._handle_ongoing_api_backoff(uid)
        if self.is_rate_limited:
            self._ensure_rate_limed_not_exhausted(uid)
        headers = {
            'User-Agent': f'{AUTH_TITLE} ({__url__}, {__version__})',
            'accept': 'application/json',
            'X-RateLimit-Precision': 'millisecond',
            'authorization': str(authorization)
        }
        if data:
            headers['content-type'] = 'application/json'

        url = urljoin(DISCORD_API_BASE_URL, route)
        args = {
            'url': url,
            'headers': headers,
            'timeout': (DISCORD_API_TIMEOUT_CONNECT, DISCORD_API_TIMEOUT_READ)
        }
        if data:
            args['json'] = data

        logger.info('%s: sending %s request to url \'%s\'', uid, method.upper(), url)
        logger.debug('%s: request headers: %s', uid, headers)
        r = getattr(requests, method)(**args)
        logger.debug(
            '%s: returned status code %d with headers: %s',
            uid,
            r.status_code,
            r.headers
        )
        logger.debug('%s: response:\n%s', uid, r.text)
        if not r.ok:
            logger.warning(
                '%s: Discord API returned error code %d and this response: %s',
                uid,
                r.status_code,
                r.text
            )

        if r.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            self._handle_new_api_backoff(r, uid)

        self._report_rate_limit_from_api(r, uid)

        if raise_for_status:
            r.raise_for_status()

        return r

    def _handle_ongoing_api_backoff(self, uid: str) -> None:
        """Check if api is currently on backoff.

        If on backoff: will do a blocking wait if it expires soon,
        else raises exception.
        """
        global_backoff_duration = self._redis.pttl(self._KEY_GLOBAL_BACKOFF_UNTIL)
        if global_backoff_duration > 0:
            if global_backoff_duration < WAIT_THRESHOLD:
                logger.info(
                    '%s: Global API backoff still ongoing for %s ms. Waiting.',
                    uid,
                    global_backoff_duration
                )
                sleep(global_backoff_duration / 1000)
            else:
                logger.info(
                    '%s: Global API backoff still ongoing for %s ms. Re-raising.',
                    uid,
                    global_backoff_duration
                )
                raise DiscordTooManyRequestsError(retry_after=global_backoff_duration)

    def _ensure_rate_limed_not_exhausted(self, uid: str) -> int:
        """Ensures that the rate limit is not exhausted.

        If exhausted: will do a blocking wait if rate limit resets soon,
        else raises exception

        returns requests remaining on success
        """
        for _ in range(RATE_LIMIT_RETRIES):
            requests_remaining = self._redis_decr_or_set(
                name=self._KEY_GLOBAL_RATE_LIMIT_REMAINING,
                value=RATE_LIMIT_MAX_REQUESTS,
                px=RATE_LIMIT_RESETS_AFTER + DURATION_CONTINGENCY
            )
            resets_in = max(
                MINIMUM_BLOCKING_WAIT,
                self._redis.pttl(self._KEY_GLOBAL_RATE_LIMIT_REMAINING)
            )
            if requests_remaining >= 0:
                logger.debug(
                    '%s: Got one of %d remaining requests until reset in %s ms',
                    uid,
                    requests_remaining + 1,
                    resets_in
                )
                return requests_remaining

            elif resets_in < WAIT_THRESHOLD:
                sleep(resets_in / 1000)
                logger.debug(
                    '%s: No requests remaining until reset in %d ms. '
                    'Waiting for reset.',
                    uid,
                    resets_in
                )
                continue

            else:
                logger.debug(
                    '%s: No requests remaining until reset in %d ms. '
                    'Raising exception.',
                    uid,
                    resets_in
                )
                raise DiscordRateLimitExhausted(resets_in)

        raise RuntimeError('Failed to handle rate limit after after too many tries.')

    def _handle_new_api_backoff(self, r: requests.Response, uid: str) -> None:
        """Raise exception for new API backoff error."""
        response = r.json()
        if 'retry_after' in response:
            try:
                retry_after = \
                    int(response['retry_after']) + DURATION_CONTINGENCY
            except ValueError:
                retry_after = DEFAULT_BACKOFF_DELAY
        else:
            retry_after = DEFAULT_BACKOFF_DELAY
        self._redis_set_if_longer(
            name=self._KEY_GLOBAL_BACKOFF_UNTIL,
            value='GLOBAL_API_BACKOFF',
            px=retry_after
        )
        logger.warning(
            "%s: Rate limit violated. Need to back off for at least %d ms",
            uid,
            retry_after
        )
        raise DiscordTooManyRequestsError(retry_after=retry_after)

    def _report_rate_limit_from_api(self, r, uid) -> None:
        """Try to log the current rate limit reported from API."""
        if (
            logger.getEffectiveLevel() <= logging.DEBUG
            and 'x-ratelimit-limit' in r.headers
            and 'x-ratelimit-remaining' in r.headers
            and 'x-ratelimit-reset-after' in r.headers
        ):
            try:
                limit = int(r.headers['x-ratelimit-limit'])
                remaining = int(r.headers['x-ratelimit-remaining'])
                reset_after = float(r.headers['x-ratelimit-reset-after']) * 1000
                if remaining + 1 == limit:
                    logger.debug(
                        '%s: Rate limit reported from API: %d requests per %s ms',
                        uid,
                        limit,
                        reset_after
                    )
            except ValueError:
                pass

    @staticmethod
    def _redis_decode(value: str) -> str:
        """Decode a string from Redis and passes through None and Booleans."""
        if value is not None and not isinstance(value, bool):
            return value.decode('utf-8')
        return value

    @staticmethod
    def _generate_hash(key: str) -> str:
        """Generate hash key for given string."""
        return md5(key.encode('utf-8')).hexdigest()

    @staticmethod
    def _sanitize_role_ids(role_ids: Iterable[int]) -> List[int]:
        """Sanitize a list of role IDs, i.e. make sure its a list of unique integers."""
        return [int(role_id) for role_id in set(role_ids)]
