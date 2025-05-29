from copy import copy
from typing import Iterable, List, Optional, Set, Tuple

from .models import Role


class RolesSet:
    """Container of Discord roles with added functionality.

    Objects of this class are immutable and work in many ways like sets.

    Ideally objects are initialized from raw API responses,
    e.g. from DiscordClient.guild.roles().

    Args:
        roles_lst: List of dicts, each defining a role
    """
    def __init__(self, roles_lst: Iterable[Role]) -> None:
        if not isinstance(roles_lst, (list, set, tuple)):
            raise TypeError('roles_lst must be of type list, set or tuple')
        self._roles = dict()
        self._roles_by_name = dict()
        for role in list(roles_lst):
            if not isinstance(role, Role):
                raise TypeError('Roles must be of type Role: %s' % role)
            self._roles[role.id] = role
            self._roles_by_name[role.name] = role

    def __repr__(self) -> str:
        if self._roles_by_name:
            roles = '"' + '", "'.join(sorted(list(self._roles_by_name.keys()))) + '"'
        else:
            roles = ""
        return f'{self.__class__.__name__}([{roles}])'

    def __eq__(self, other):
        if isinstance(other, type(self)):
            return self.ids() == other.ids()
        return NotImplemented

    def __hash__(self):
        return hash(tuple(sorted(self._roles.keys())))

    def __iter__(self):
        yield from self._roles.values()

    def __contains__(self, item) -> bool:
        return int(item) in self._roles

    def __len__(self):
        return len(self._roles.keys())

    def has_roles(self, role_ids: Set[int]) -> bool:
        """True if this objects contains all roles defined by given role_ids
        incl. managed roles.
        """
        role_ids = {int(id) for id in role_ids}
        all_role_ids = self._roles.keys()
        return role_ids.issubset(all_role_ids)

    def ids(self) -> Set[int]:
        """Set of all role IDs."""
        return set(self._roles.keys())

    def subset(
        self,
        role_ids: Iterable[int] = None,
        managed_only: bool = False,
        role_names: Iterable[str] = None
    ) -> "RolesSet":
        """Create instance containing the subset of roles

        Args:
            role_ids: role ids must be in the provided list
            managed_only: roles must be managed
            role_names: role names must match provided list (not case sensitive)
        """
        if role_ids is not None:
            role_ids = {int(id) for id in role_ids}

        if role_ids is not None and not managed_only:
            return type(self)([
                role for role_id, role in self._roles.items() if role_id in role_ids
            ])

        elif role_ids is None and managed_only:
            return type(self)([
                role for _, role in self._roles.items() if role.managed
            ])

        elif role_ids is not None and managed_only:
            return type(self)([
                role for role_id, role in self._roles.items()
                if role_id in role_ids and role.managed
            ])

        elif role_ids is None and managed_only is False and role_names is not None:
            role_names = {Role.sanitize_name(name).lower() for name in role_names}
            return type(self)([
                role for role in self._roles.values()
                if role.name.lower() in role_names
            ])

        return copy(self)

    def union(self, other: object) -> "RolesSet":
        """Create instance that is the union of this roles object with other."""
        return type(self)(list(self) + list(other))

    def difference(self, other: object) -> "RolesSet":
        """Create instance that only contains the roles
        that exist in the current objects, but not in other.
        """
        new_ids = self.ids().difference(other.ids())
        return self.subset(role_ids=new_ids)

    def role_by_name(self, role_name: str) -> Optional[Role]:
        """Role if one with matching name is found else None."""
        role_name = Role.sanitize_name(role_name)
        if role_name in self._roles_by_name:
            return self._roles_by_name[role_name]
        return None

    @classmethod
    def create_from_matched_roles(
        cls, matched_roles: List[Tuple[Role, bool]]
    ) -> "RolesSet":
        """Create new instance from the given list of matches roles.

        Args:
            matches_roles: list of matches roles
        """
        raw_roles = [x[0] for x in matched_roles]
        return cls(raw_roles)
