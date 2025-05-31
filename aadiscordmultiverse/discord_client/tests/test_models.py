import json
from pathlib import Path
from unittest import TestCase

from ..models import Guild, GuildMember, Role, User
from .factories import create_guild, create_guild_member, create_role, create_user


def _fetch_example_objects() -> dict:
    path = Path(__file__).parent / "example_objects.json"
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


class TestUser(TestCase):
    def test_should_create_new_object(self):
        # when
        obj = User(id="42", username=123, discriminator=456)
        # then
        self.assertEqual(obj.id, 42)
        self.assertEqual(obj.username, "123")
        self.assertTrue(obj.discriminator, "456")

    def test_should_create_from_dict(self):
        # given
        data = example_objects["users"]["80351110224678912"]
        # when
        obj = User.from_dict(data)
        # then
        self.assertEqual(obj.id, 80351110224678912)
        self.assertEqual(obj.username, "Nelly")
        self.assertEqual(obj.discriminator, "1337")


class TestRole(TestCase):
    def test_should_create_new_object_with_defaults(self):
        # when
        obj = Role(id="42", name="x" * 110)
        # then
        self.assertEqual(obj.id, 42)
        self.assertEqual(obj.name, "x" * 100)
        self.assertFalse(obj.managed)

    def test_should_create_new_object(self):
        # when
        obj = Role(id=42, name="name", managed=1)
        # then
        self.assertEqual(obj.id, 42)
        self.assertEqual(obj.name, "name")
        self.assertTrue(obj.managed)

    def test_should_create_from_dict(self):
        # given
        data = example_objects["roles"]["41771983423143936"]
        # when
        obj = Role.from_dict(data)
        # then
        self.assertEqual(obj.id, 41771983423143936)
        self.assertEqual(obj.name, "WE DEM BOYZZ!!!!!!")
        self.assertFalse(obj.managed)

    def test_should_convert_to_dict(self):
        # given
        role = create_role(id=42, name="Special Name", managed=True)
        # when/then
        self.assertDictEqual(
            role.asdict(), {"id": 42, "name": "Special Name", "managed": True}
        )

    def test_sanitize_role_name(self):
        # given
        role_name_input = "x" * 110
        role_name_expected = "x" * 100
        # when
        result = Role.sanitize_name(role_name_input)
        # then
        self.assertEqual(result, role_name_expected)


class TestGuild(TestCase):
    def test_should_create_new_object(self):
        # given
        role_a = create_role()
        # when
        obj = Guild(id="42", name=123, roles=[role_a])
        # then
        self.assertEqual(obj.id, 42)
        self.assertEqual(obj.name, "123")
        self.assertEqual(obj.roles, frozenset([role_a]))

    def test_should_create_from_dict(self):
        # given
        data = example_objects["guilds"]["2909267986263572999"]
        # when
        obj = Guild.from_dict(data)
        # then
        self.assertEqual(obj.id, 2909267986263572999)
        self.assertEqual(obj.name, "Mason's Test Server")
        (first_role,) = obj.roles
        self.assertEqual(first_role.id, 2909267986263572999)

    def test_should_raise_error_when_role_type_is_wrong(self):
        with self.assertRaises(TypeError):
            create_guild(roles=[create_role(), "invalid"])


class TestGuildMember(TestCase):
    def test_should_create_new_object(self):
        # given
        user = create_user()
        # when
        obj = GuildMember(user=user, nick="x" * 40, roles=[1, 2])
        # then
        self.assertEqual(obj.user, user)
        self.assertEqual(obj.nick, "x" * 32)
        self.assertEqual(obj.roles, frozenset([1, 2]))

    def test_should_create_from_dict_empty(self):
        # given
        data = example_objects["guildMembers"]["1"]
        # when
        obj = GuildMember.from_dict(data)
        # then
        self.assertIsNone(obj.user)
        self.assertSetEqual(obj.roles, set())
        self.assertIsNone(obj.nick)

    def test_should_create_from_dict_full(self):
        # given
        data = example_objects["guildMembers"]["2"]
        # when
        obj = GuildMember.from_dict(data)
        # then
        self.assertEqual(obj.user.username, "Nelly")
        self.assertSetEqual(obj.roles, {197150972374548480, 41771983423143936})
        self.assertEqual(obj.nick, "Nelly the great")

    def test_should_raise_error_when_user_type_is_wrong(self):
        with self.assertRaises(TypeError):
            create_guild_member(user="invalid")

    def test_should_raise_error_when_role_type_is_wrong(self):
        with self.assertRaises(TypeError):
            GuildMember(roles=[1, 2, "invalid"])

    def test_sanitize_nick(self):
        # given
        nick_input = "x" * 40
        nick_expected = "x" * 32
        # when
        result = GuildMember.sanitize_nick(nick_input)
        # then
        self.assertEqual(result, nick_expected)


example_objects = _fetch_example_objects()
