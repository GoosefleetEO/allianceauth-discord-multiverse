"""Implementation of Discord objects used by this client.

Note that only those objects and properties are implemented, which are needed by AA.

Names and types are mirrored from the API whenever possible.
Discord's snowflake type (used by Discord IDs) is implemented as int.
"""

from dataclasses import asdict, dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class User:
    """A user on Discord."""

    id: int
    username: str
    discriminator: str

    def __post_init__(self):
        object.__setattr__(self, "id", int(self.id))
        object.__setattr__(self, "username", str(self.username))
        object.__setattr__(self, "discriminator", str(self.discriminator))

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        """Create object from dictionary as received from the API."""
        return cls(
            id=int(data["id"]),
            username=data["username"],
            discriminator=data["discriminator"],
        )


@dataclass(frozen=True)
class Role:
    """A role on Discord."""

    _ROLE_NAME_MAX_CHARS = 100

    id: int
    name: str
    managed: bool = False

    def __post_init__(self):
        object.__setattr__(self, "id", int(self.id))
        object.__setattr__(self, "name", self.sanitize_name(self.name))
        object.__setattr__(self, "managed", bool(self.managed))

    def asdict(self) -> dict:
        """Convert object into a dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Role":
        """Create object from dictionary as received from the API."""
        return cls(id=int(data["id"]), name=data["name"], managed=data["managed"])

    @classmethod
    def sanitize_name(cls, role_name: str) -> str:
        """Shorten too long names if necessary."""
        return str(role_name)[: cls._ROLE_NAME_MAX_CHARS]


@dataclass(frozen=True)
class Guild:
    """A guild on Discord."""

    id: int
    name: str
    roles: FrozenSet[Role]

    def __post_init__(self):
        object.__setattr__(self, "id", int(self.id))
        object.__setattr__(self, "name", str(self.name))
        for role in self.roles:
            if not isinstance(role, Role):
                raise TypeError("roles can only contain Role objects.")
        object.__setattr__(self, "roles", frozenset(self.roles))

    @classmethod
    def from_dict(cls, data: dict) -> "Guild":
        """Create object from dictionary as received from the API."""
        return cls(
            id=int(data["id"]),
            name=data["name"],
            roles=frozenset(Role.from_dict(obj) for obj in data["roles"]),
        )


@dataclass(frozen=True)
class GuildMember:
    """A member of a guild on Discord."""

    _NICK_MAX_CHARS = 32

    roles: FrozenSet[int]
    nick: str = None
    user: User = None

    def __post_init__(self):
        if self.nick:
            object.__setattr__(self, "nick", self.sanitize_nick(self.nick))
        if self.user and not isinstance(self.user, User):
            raise TypeError("user must be of type User")
        for role in self.roles:
            if not isinstance(role, int):
                raise TypeError("roles can only contain ints")
        object.__setattr__(self, "roles", frozenset(self.roles))

    @classmethod
    def from_dict(cls, data: dict) -> "GuildMember":
        """Create object from dictionary as received from the API."""
        params = {"roles": {int(obj) for obj in data["roles"]}}
        if data.get("user"):
            params["user"] = User.from_dict(data["user"])
        if data.get("nick"):
            params["nick"] = data["nick"]
        return cls(**params)

    @classmethod
    def sanitize_nick(cls, nick: str) -> str:
        """Sanitize a nick, i.e. shorten too long strings if necessary."""
        return str(nick)[: cls._NICK_MAX_CHARS]
