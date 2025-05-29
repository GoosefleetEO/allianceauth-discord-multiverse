import json
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import requests
import requests_mock
from redis import Redis
from requests.exceptions import HTTPError

from allianceauth import __title__ as AUTH_TITLE
from allianceauth import __url__, __version__
from allianceauth.utils.testing import NoSocketsTestCase

from ...utils import set_logger_to_file
from ..client import (
    DEFAULT_BACKOFF_DELAY,
    DURATION_CONTINGENCY,
    DiscordClient,
    RolesSet,
)
from ..exceptions import DiscordRateLimitExhausted, DiscordTooManyRequestsError
from .factories import (
    TEST_BOT_TOKEN,
    TEST_GUILD_ID,
    TEST_ROLE_ID,
    TEST_USER_ID,
    TEST_USER_NAME,
    create_discord_error_response_unknown_member,
    create_discord_guild_member_object,
    create_discord_guild_object,
    create_discord_role_object,
    create_guild,
    create_guild_member,
    create_matched_role,
    create_role,
    create_user,
)

logger = set_logger_to_file(
    'allianceauth.services.modules.discord.discord_client.client', __file__
)

MODULE_PATH = 'allianceauth.services.modules.discord.discord_client.client'
API_BASE_URL = 'https://discord.com/api/'

TEST_RETRY_AFTER = 3000

DEFAULT_REQUEST_HEADERS = {
    'User-Agent': f'{AUTH_TITLE} ({__url__}, {__version__})',
    'accept': 'application/json',
    'authorization': 'Bot ' + TEST_BOT_TOKEN
}

# default mock redis client to use
mock_redis = MagicMock(**{
    'get.return_value': None,
    'pttl.return_value': -1,
})


# default mock function to simulate sleep
def my_sleep(value):
    if value < 0:
        raise ValueError('sleep length must be non-negative')


class DiscordClientStub(DiscordClient):
    """DiscordClient with stubbed lua wrappers for easier testing."""

    def _redis_set_if_longer(self, name: str, value: str, px: int):
        return True

    def _redis_decr_or_set(self, name: str, value: str, px: int):
        return 5


class TestBasicsAndHelpers(NoSocketsTestCase):

    def test_can_create_object(self):
        # when
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        # then
        self.assertIsInstance(client, DiscordClient)
        self.assertEqual(client.access_token, TEST_BOT_TOKEN)

    def test_should_raise_error_when_trying_to_create_object_without_token(self):
        # when/then
        with self.assertRaises(Exception):
            DiscordClient("", mock_redis)

    def test_repr(self):
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        expected = 'DiscordClient(access_token=...UVWXY)'
        self.assertEqual(repr(client), expected)

    def test_can_set_rate_limiting(self):
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis, is_rate_limited=False)
        self.assertFalse(client.is_rate_limited)

        client = DiscordClient(TEST_BOT_TOKEN, mock_redis, is_rate_limited=True)
        self.assertTrue(client.is_rate_limited)

    @patch(MODULE_PATH + '.get_redis_client', spec=True)
    def test_use_default_redis_if_none_provided(self, mock_get_redis_client):
        # given
        my_redis = MagicMock(spec=Redis)
        mock_get_redis_client.return_value = my_redis
        # when
        client = DiscordClient(TEST_BOT_TOKEN)
        # then
        self.assertEqual(client._redis, my_redis)

    @patch(MODULE_PATH + '.get_redis_client')
    def test_raise_exception_if_redis_client_not_found(self, mock_get_redis_client):
        # given
        mock_get_redis_client.return_value = None
        # when
        with self.assertRaises(RuntimeError):
            DiscordClient(TEST_BOT_TOKEN)


@requests_mock.Mocker()
class TestOtherMethods(NoSocketsTestCase):

    def setUp(self):
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        self.headers = DEFAULT_REQUEST_HEADERS

    def test_user_get_current(self, requests_mocker):
        user = create_user()
        headers = {
            'accept': 'application/json',
            'authorization': 'Bearer accesstoken'
        }
        requests_mocker.register_uri(
            'GET',
            f'{API_BASE_URL}users/@me',
            request_headers=headers,
            json=asdict(user)
        )
        client = DiscordClientStub('accesstoken', mock_redis)
        result = client.current_user()
        self.assertEqual(result, user)

    def test_get_infos(self, requests_mocker):
        requests_mocker.get(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}',
            request_headers=self.headers,
            json=create_discord_guild_object(id=1, name="dummy")
        )
        result = self.client.guild_infos(TEST_GUILD_ID)
        self.assertEqual(result, create_guild(id=1, name="dummy"))


@requests_mock.Mocker()
class TestGuildRoles(NoSocketsTestCase):

    def setUp(self):
        self.url = f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles'

    def test_without_cache(self, requests_mocker):
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json=[create_discord_role_object(1, "alpha")]
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_roles(TEST_GUILD_ID, use_cache=False)
        self.assertSetEqual(result, {create_role(id=1, name="alpha")})
        self.assertTrue(my_mock_redis.set.called)

    def test_return_from_cache_if_in_cache(self, requests_mocker):
        my_mock_redis = MagicMock(**{
            'get.return_value': (
                json.dumps([create_discord_role_object(1, "alpha")]).encode('utf8')
            )
        })
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_roles(TEST_GUILD_ID)
        self.assertSetEqual(result, {create_role(id=1, name="alpha")})
        self.assertFalse(my_mock_redis.set.called)

    def test_return_from_api_and_save_to_cache_if_not_in_cache(
        self, requests_mocker
    ):
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json=[create_discord_role_object(1, "alpha")]
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_roles(TEST_GUILD_ID)
        self.assertEqual(result, {create_role(id=1, name="alpha")})
        self.assertTrue(my_mock_redis.set.called)

    def test_dont_save_in_cache_if_api_returns_invalid_response_1(
        self, requests_mocker
    ):
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json={}
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        with self.assertRaises(RuntimeError):
            client.guild_roles(TEST_GUILD_ID)

    def test_dont_save_in_cache_if_api_returns_invalid_response_2(
        self, requests_mocker
    ):
        expected = "api returns string"
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json=expected
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        with self.assertRaises(RuntimeError):
            client.guild_roles(TEST_GUILD_ID)


@requests_mock.Mocker()
class TestGuildMember(NoSocketsTestCase):

    def setUp(self):
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        self.headers = DEFAULT_REQUEST_HEADERS

    def test_return_guild_member_when_ok(self, requests_mocker):
        requests_mocker.get(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}',
            request_headers=self.headers,
            json=create_discord_guild_member_object()
        )
        result = self.client.guild_member(TEST_GUILD_ID, TEST_USER_ID)
        expected = create_guild_member()
        self.assertEqual(result, expected)

    def test_return_none_if_member_not_known(self, requests_mocker):
        requests_mocker.get(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}',
            request_headers=self.headers,
            status_code=404,
            json=create_discord_error_response_unknown_member()
        )
        result = self.client.guild_member(TEST_GUILD_ID, TEST_USER_ID)
        self.assertIsNone(result)

    def test_raise_exception_on_error(self, requests_mocker):
        requests_mocker.get(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}',
            request_headers=self.headers,
            status_code=500
        )
        with self.assertRaises(HTTPError):
            self.client.guild_member(TEST_GUILD_ID, TEST_USER_ID)


class TestGuildGetName(NoSocketsTestCase):

    @patch(MODULE_PATH + '.DiscordClient.guild_infos', spec=True)
    def test_returns_from_cache_if_found(self, mock_guild_get_infos):
        guild_name = 'Omega'
        my_mock_redis = MagicMock(**{'get.return_value': guild_name.encode('utf8')})
        mock_guild_get_infos.side_effect = RuntimeError
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_name(TEST_GUILD_ID)
        self.assertEqual(result, guild_name)
        self.assertTrue(my_mock_redis.get.called)
        self.assertFalse(my_mock_redis.set.called)

    @patch(MODULE_PATH + '.DiscordClient.guild_infos', spec=True)
    def test_fetches_from_server_if_not_found_in_cache_and_stores_in_cache(
        self, mock_guild_get_infos
    ):
        guild_name = 'Omega'
        my_mock_redis = MagicMock(**{'get.return_value': False})
        mock_guild_get_infos.return_value = create_guild(name=guild_name)
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_name(TEST_GUILD_ID)
        self.assertEqual(result, guild_name)
        self.assertTrue(my_mock_redis.get.called)
        self.assertTrue(my_mock_redis.set.called)

    @patch(MODULE_PATH + '.DiscordClient.guild_infos', spec=True)
    def test_fetches_from_server_if_asked_to_ignore_cache_and_stores_in_cache(
        self, mock_guild_get_infos
    ):
        guild_name = 'Omega'
        my_mock_redis = MagicMock(**{'get.return_value': False})
        mock_guild_get_infos.return_value = create_guild(name=guild_name)
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        result = client.guild_name(TEST_GUILD_ID, use_cache=False)
        self.assertFalse(my_mock_redis.get.called)
        self.assertEqual(result, guild_name)
        self.assertTrue(my_mock_redis.set.called)

    @patch(MODULE_PATH + '.DiscordClient.guild_infos', spec=True)
    def test_return_empty_if_not_found_in_cache_and_server_has_error(
        self, mock_guild_get_infos
    ):
        # given
        my_mock_redis = MagicMock(**{'get.return_value': False})
        mock_guild_get_infos.side_effect = HTTPError
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        # when
        result = client.guild_name(TEST_GUILD_ID)
        # then
        self.assertEqual(result, '')
        self.assertTrue(my_mock_redis.get.called)
        self.assertFalse(my_mock_redis.set.called)


@requests_mock.Mocker()
class TestCreateGuildRole(NoSocketsTestCase):

    def setUp(self):
        self.request_url = f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles'
        self.my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        self.client = DiscordClientStub(TEST_BOT_TOKEN, self.my_mock_redis)

    def test_guild_create_role_normal(self, requests_mocker):
        role_name_input = 'x' * 120
        role_name_used = 'x' * 100
        expected = create_discord_role_object(id=1, name=role_name_used)

        requests_mocker.post(
            self.request_url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            text=json.dumps(expected),
        )
        result = self.client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=role_name_input
        )
        self.assertEqual(result, create_role(id=1, name=role_name_used))
        self.assertTrue(self.my_mock_redis.delete.called)

    def test_guild_create_role_empty_response(self, requests_mocker):
        requests_mocker.post(
            self.request_url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            text=json.dumps({}),
        )
        result = self.client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name='dummy'
        )
        self.assertIsNone(result)
        self.assertFalse(self.my_mock_redis.delete.called)


@requests_mock.Mocker()
class TestGuildDeleteRole(NoSocketsTestCase):

    def setUp(self):
        self.request_url = \
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles/{TEST_ROLE_ID}'
        self.my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        self.client = DiscordClientStub(TEST_BOT_TOKEN, self.my_mock_redis)

    def test_guild_delete_role_success(self, requests_mocker):
        requests_mocker.delete(
            self.request_url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            status_code=204
        )
        result = self.client.delete_guild_role(
            guild_id=TEST_GUILD_ID, role_id=TEST_ROLE_ID
        )
        self.assertTrue(result)
        self.assertTrue(self.my_mock_redis.delete.called)

    def test_guild_delete_role_failed(self, requests_mocker):
        requests_mocker.delete(
            self.request_url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            status_code=200
        )
        result = self.client.delete_guild_role(
            guild_id=TEST_GUILD_ID, role_id=TEST_ROLE_ID
        )
        self.assertFalse(result)
        self.assertFalse(self.my_mock_redis.delete.called)


@requests_mock.Mocker()
class TestGuildAddMember(NoSocketsTestCase):

    def setUp(self):
        self.access_token = 'accesstoken'
        self.headers = DEFAULT_REQUEST_HEADERS
        self.request_url = \
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}'
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)

    def test_create_new_without_params(self, requests_mocker):

        def data_matcher(request):
            expected = {'access_token': self.access_token}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=201,
        )
        result = self.client.add_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            access_token=self.access_token
        )
        self.assertTrue(result)

    def test_create_existing_without_params(self, requests_mocker):

        def data_matcher(request):
            expected = {'access_token': self.access_token}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=204,
        )
        result = self.client.add_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            access_token=self.access_token
        )
        self.assertIsNone(result)

    def test_create_failed_without_params(self, requests_mocker):

        def data_matcher(request):
            expected = {'access_token': self.access_token}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=200,
        )
        result = self.client.add_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            access_token=self.access_token
        )
        self.assertFalse(result)

    def test_create_new_with_roles(self, requests_mocker):

        role_ids = [1, 2]

        def data_matcher(request):
            expected = {
                'access_token': self.access_token,
                'roles': role_ids
            }
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=201,
        )
        result = self.client.add_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            access_token=self.access_token,
            role_ids=role_ids
        )
        self.assertTrue(result)

    def test_raise_exception_on_invalid_roles(self, requests_mocker):
        with self.assertRaises(ValueError):
            self.client.add_guild_member(
                guild_id=TEST_GUILD_ID,
                user_id=TEST_USER_ID,
                access_token=self.access_token,
                role_ids=['abc', 'def']
            )

    def test_create_new_with_nick(self, requests_mocker):

        nick_input = 'x' * 50
        nick_used = 'x' * 32

        def data_matcher(request):
            expected = {
                'access_token': self.access_token,
                'nick': nick_used
            }
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=201,
        )
        result = self.client.add_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            access_token=self.access_token,
            nick=nick_input
        )
        self.assertTrue(result)


@requests_mock.Mocker()
class TestGuildModifyMember(NoSocketsTestCase):

    def setUp(self):
        self.access_token = 'accesstoken'
        self.headers = DEFAULT_REQUEST_HEADERS.copy()
        self.headers['content-type'] = 'application/json'
        self.request_url = \
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}'
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)

    def test_can_update_roles(self, requests_mocker):
        role_ids = [1, 2]

        def data_matcher(request):
            expected = {'roles': role_ids}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'patch',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=204,
        )
        result = self.client.modify_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            role_ids=role_ids
        )
        self.assertTrue(result)

    def test_can_update_nick(self, requests_mocker):
        nick_input = 'x' * 50
        nick_used = 'x' * 32

        def data_matcher(request):
            expected = {'nick': nick_used}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'patch',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=204,
        )
        result = self.client.modify_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            nick=nick_input
        )
        self.assertTrue(result)

    def test_can_update_roles_and_nick(self, requests_mocker):
        role_ids = [1, 2]

        def data_matcher(request):
            expected = {
                'roles': role_ids,
                'nick': TEST_USER_NAME
            }
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'patch',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=204,
        )
        result = self.client.modify_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            role_ids=role_ids,
            nick=TEST_USER_NAME,
        )
        self.assertTrue(result)

    def test_returns_none_if_member_is_unknown(self, requests_mocker):

        def data_matcher(request):
            expected = {'nick': TEST_USER_NAME}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'patch',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=404,
            json=create_discord_error_response_unknown_member()
        )
        result = self.client.modify_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            nick=TEST_USER_NAME
        )
        self.assertIsNone(result)

    def test_returns_false_if_unsuccessful(self, requests_mocker):

        def data_matcher(request):
            expected = {'nick': TEST_USER_NAME}
            return (json.loads(request.text) == expected)

        requests_mocker.register_uri(
            'patch',
            self.request_url,
            request_headers=self.headers,
            additional_matcher=data_matcher,
            status_code=200,
        )
        result = self.client.modify_guild_member(
            guild_id=TEST_GUILD_ID,
            user_id=TEST_USER_ID,
            nick=TEST_USER_NAME
        )
        self.assertFalse(result)

    def test_raise_exception_on_invalid_roles(self, requests_mocker):
        with self.assertRaises(ValueError):
            self.client.modify_guild_member(
                guild_id=TEST_GUILD_ID,
                user_id=TEST_USER_ID,
                role_ids=['abc', 'def']
            )

    def test_raise_exception_if_role_ids_not_list_like(self, requests_mocker):
        with self.assertRaises(TypeError):
            self.client.modify_guild_member(
                guild_id=TEST_GUILD_ID,
                user_id=TEST_USER_ID,
                role_ids='I am not a list'
            )

    def test_raise_exception_on_missing_params(
        self, requests_mocker
    ):
        with self.assertRaises(ValueError):
            self.client.modify_guild_member(
                guild_id=TEST_GUILD_ID,
                user_id=TEST_USER_ID
            )


class TestGuildRemoveMember(NoSocketsTestCase):

    def setUp(self):
        self.headers = DEFAULT_REQUEST_HEADERS
        self.request_url = \
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}'
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)

    @requests_mock.Mocker()
    def test_returns_true_on_success(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=204
        )
        result = self.client.remove_guild_member(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID
        )
        self.assertTrue(result)

    @requests_mock.Mocker()
    def test_returns_none_if_member_unknown(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=404,
            json=create_discord_error_response_unknown_member()
        )
        result = self.client.remove_guild_member(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID
        )
        self.assertIsNone(result)

    @requests_mock.Mocker()
    def test_raise_exception_on_404_if_member_known(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=404,
            json={}
        )
        with self.assertRaises(HTTPError):
            self.client.remove_guild_member(
                guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID
            )

    @requests_mock.Mocker()
    def test_raise_exception_on_404_if_no_api_response(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=404
        )
        with self.assertRaises(HTTPError):
            self.client.remove_guild_member(
                guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID
            )

    @requests_mock.Mocker()
    def test_returns_false_when_not_successful(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=200
        )
        result = self.client.remove_guild_member(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID
        )
        self.assertFalse(result)


class TestGuildMemberAddRole(NoSocketsTestCase):

    def setUp(self):
        self.headers = DEFAULT_REQUEST_HEADERS
        self.request_url = (
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}'
            f'/roles/{TEST_ROLE_ID}'
        )
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)

    @requests_mock.Mocker()
    def test_returns_true_on_success(self, requests_mocker):
        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            status_code=204
        )
        result = self.client.add_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertTrue(result)

    @requests_mock.Mocker()
    def test_return_none_if_member_not_known(self, requests_mocker):
        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            status_code=404,
            json=create_discord_error_response_unknown_member()
        )
        result = self.client.add_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertIsNone(result)

    @requests_mock.Mocker()
    def test_returns_false_when_not_successful(self, requests_mocker):
        requests_mocker.register_uri(
            'PUT',
            self.request_url,
            request_headers=self.headers,
            status_code=200
        )
        result = self.client.add_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertFalse(result)


class TestGuildMemberRemoveRole(NoSocketsTestCase):

    def setUp(self):
        self.headers = DEFAULT_REQUEST_HEADERS
        self.request_url = (
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/members/{TEST_USER_ID}'
            f'/roles/{TEST_ROLE_ID}'
        )
        self.client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)

    @requests_mock.Mocker()
    def test_returns_true_on_success(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=204
        )
        result = self.client.remove_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertTrue(result)

    @requests_mock.Mocker()
    def test_return_none_if_member_not_known(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=404,
            json=create_discord_error_response_unknown_member()
        )
        result = self.client.remove_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertIsNone(result)

    @requests_mock.Mocker()
    def test_returns_false_when_not_successful(self, requests_mocker):
        requests_mocker.register_uri(
            'DELETE',
            self.request_url,
            request_headers=self.headers,
            status_code=200
        )
        result = self.client.remove_guild_member_role(
            guild_id=TEST_GUILD_ID, user_id=TEST_USER_ID, role_id=TEST_ROLE_ID
        )
        self.assertFalse(result)


@patch(MODULE_PATH + '.DiscordClient.guild_roles', spec=True)
@patch(MODULE_PATH + '.DiscordClient.guild_member', spec=True)
class TestGuildMemberRoles(NoSocketsTestCase):
    def test_should_return_member_roles(
        self, mock_guild_member, mock_guild_roles
    ):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        mock_guild_member.return_value = create_guild_member(roles=[1])
        mock_guild_roles.return_value = {role_a, role_b}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.guild_member_roles(TEST_GUILD_ID, TEST_USER_ID)
        # then
        self.assertSetEqual(result.ids(), {1})

    def test_should_return_none_when_no_member(
        self, mock_guild_member, mock_guild_roles
    ):
        # given
        mock_guild_member.return_value = None
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.guild_member_roles(TEST_GUILD_ID, TEST_USER_ID)
        # then
        self.assertIsNone(result)

    def test_should_raise_exception_if_member_has_unknown_roles(
        self, mock_guild_member, mock_guild_roles
    ):
        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        mock_guild_member.return_value = create_guild_member(roles=[1, 99])
        mock_guild_roles.return_value = {role_a, role_b}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when/then
        roles = client.guild_member_roles(TEST_GUILD_ID, TEST_USER_ID)
        self.assertEqual(roles, RolesSet([role_a]))

    # TODO: Re-enable after adding Discord general error handling
    # def test_should_raise_exception_if_member_info_is_invalid(
    #     self, mock_guild_member, mock_guild_roles
    # ):
    #     # given
    #     member_info = create_guild_member(roles=[1])
    #     del(member_info["roles"])
    #     mock_guild_member.return_value = member_info
    #     mock_guild_roles.return_value = [ROLE_ALPHA, ROLE_BRAVO]
    #     client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
    #     # when/then
    #     with self.assertRaises(RuntimeError):
    #         client.guild_member_roles(TEST_GUILD_ID, TEST_USER_ID)

    def test_refresh_guild_roles_user_roles_dont_not_match(
        self, mock_guild_member, mock_guild_roles
    ):
        def my_guild_roles(guild_id, use_cache=True):
            if use_cache:
                return {role_a}
            return {role_a, role_b}

        # given
        role_a = create_role(id=1)
        role_b = create_role(id=2)
        mock_guild_member.return_value = create_guild_member(roles=[1, 2])
        mock_guild_roles.side_effect = my_guild_roles
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.guild_member_roles(TEST_GUILD_ID, TEST_USER_ID)
        # then
        self.assertSetEqual(result.ids(), {1, 2})
        self.assertEqual(mock_guild_roles.call_count, 2)


class TestMatchGuildRolesToName(NoSocketsTestCase):

    def setUp(self):
        self.url = f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles'

    @requests_mock.Mocker()
    def test_return_role_if_known(self, requests_mocker):
        # given
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json=[create_discord_role_object(1, "alpha")]
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        # when
        result = client.match_role_from_name(TEST_GUILD_ID, "alpha")
        # then
        self.assertEqual(result, create_role(id=1, name="alpha"))

    @requests_mock.Mocker()
    def test_return_empty_none_if_not_known(self, requests_mocker):
        # given
        my_mock_redis = MagicMock(**{
            'get.return_value': None,
            'pttl.return_value': -1,
        })
        requests_mocker.get(
            url=self.url,
            request_headers=DEFAULT_REQUEST_HEADERS,
            json=[create_discord_role_object(1, "alpha")]
        )
        client = DiscordClientStub(TEST_BOT_TOKEN, my_mock_redis)
        # when
        result = client.match_role_from_name(TEST_GUILD_ID, "unknown")
        # then
        self.assertIsNone(result)


@patch(MODULE_PATH + '.DiscordClient.create_guild_role', spec=True)
@patch(MODULE_PATH + '.DiscordClient.guild_roles', spec=True)
class TestMatchOrCreateGuildRolesToName(NoSocketsTestCase):

    def test_return_role_if_known(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        role_a = create_role(name="alpha")
        role_b = create_role(name="bravo")
        mock_guild_get_roles.return_value = {role_a, role_b}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_role_from_name(TEST_GUILD_ID, "alpha")
        # then
        self.assertEqual(result, create_matched_role(role_a, False))
        self.assertFalse(mock_guild_create_role.called)

    def test_create_role_if_not_known_and_return_it(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        role_existing = create_role()
        role_new = create_role(name='echo')
        mock_guild_get_roles.return_value = {role_existing}
        mock_guild_create_role.return_value = role_new
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_role_from_name(TEST_GUILD_ID, 'echo')
        # then
        expected = (role_new, True)
        self.assertEqual(result, expected)
        self.assertTrue(mock_guild_create_role.called)

    @patch(MODULE_PATH + '.DISCORD_DISABLE_ROLE_CREATION', True)
    def test_return_none_if_role_creation_is_disabled(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        mock_guild_get_roles.return_value = {create_role()}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_role_from_name(TEST_GUILD_ID, 'echo')
        # then
        self.assertIsNone(result[0])
        self.assertFalse(result[1])
        self.assertFalse(mock_guild_create_role.called)

    def test_raise_exception_if_name_has_invalid_type(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        mock_guild_get_roles.return_value = {}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        with self.assertRaises(TypeError):
            client.match_or_create_role_from_name(TEST_GUILD_ID, 666)


@patch(MODULE_PATH + '.DiscordClient.create_guild_role', spec=True)
@patch(MODULE_PATH + '.DiscordClient.guild_roles', spec=True)
class TestMatchOrCreateGuildRolesToNames(NoSocketsTestCase):

    def test_return_roles_if_known(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        role_a = create_role(name='alpha')
        role_b = create_role(name='bravo')
        mock_guild_get_roles.return_value = {role_a, role_b}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(
            TEST_GUILD_ID, ['alpha', 'bravo']
        )
        # then
        expected = [create_matched_role(role_a), create_matched_role(role_b)]
        self.assertEqual(
            RolesSet.create_from_matched_roles(result),
            RolesSet.create_from_matched_roles(expected)
        )
        self.assertFalse(mock_guild_create_role.called)

    def test_return_roles_if_known_and_create_if_not_known(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        role_existing = create_role(name='alpha')
        role_new = create_role(name='echo')
        mock_guild_get_roles.return_value = {role_existing}
        mock_guild_create_role.return_value = role_new
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(
            TEST_GUILD_ID, ['alpha', 'echo']
        )
        # then
        expected = [
            create_matched_role(role_existing), create_matched_role(role_new, True)
        ]
        self.assertEqual(
            RolesSet.create_from_matched_roles(result),
            RolesSet.create_from_matched_roles(expected)
        )
        self.assertTrue(mock_guild_create_role.called)

    @patch(MODULE_PATH + '.DISCORD_DISABLE_ROLE_CREATION', True)
    def test_do_not_create_unknown_roles_when_so_configured(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        role_a = create_role(name='alpha')
        mock_guild_get_roles.return_value = {role_a}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(
            TEST_GUILD_ID, ['alpha', 'echo']
        )
        # then
        expected = [create_matched_role(role_a)]
        self.assertEqual(
            RolesSet.create_from_matched_roles(result),
            RolesSet.create_from_matched_roles(expected)
        )
        self.assertFalse(mock_guild_create_role.called)

    def test_consolidate_roles_of_same_name(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        role_a = create_role(name='alpha')
        mock_guild_get_roles.return_value = {role_a}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(
            TEST_GUILD_ID, ['alpha', 'alpha']
        )
        # then
        expected = [create_matched_role(role_a)]
        self.assertEqual(
            RolesSet.create_from_matched_roles(result),
            RolesSet.create_from_matched_roles(expected)
        )
        self.assertFalse(mock_guild_create_role.called)

    def test_consolidate_roles_of_same_name_after_sanitation(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        base_role_name = 'x' * 100
        role = create_role(name=base_role_name)
        role_names = [base_role_name + '1', base_role_name + '2']
        mock_guild_get_roles.return_value = {role}
        mock_guild_create_role.return_value = role
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(TEST_GUILD_ID, role_names)
        # then
        expected = [create_matched_role(role)]
        self.assertEqual(
            RolesSet.create_from_matched_roles(result),
            RolesSet.create_from_matched_roles(expected)
        )
        self.assertFalse(mock_guild_create_role.called)

    def test_should_return_empty_list_when_no_names_given(
        self, mock_guild_get_roles, mock_guild_create_role,
    ):
        # given
        mock_guild_get_roles.return_value = {create_role()}
        client = DiscordClientStub(TEST_BOT_TOKEN, mock_redis)
        # when
        result = client.match_or_create_roles_from_names(TEST_GUILD_ID, [])
        # then
        self.assertListEqual(result, [])
        self.assertFalse(mock_guild_create_role.called)


class TestMatchOrCreateRolesFromNames2(NoSocketsTestCase):
    def test_should_return_roles(self):
        # given
        role_a = create_role(name='alpha')
        role_b = create_role(name='bravo')
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        matched_roles = [
            create_matched_role(role_a, False), create_matched_role(role_b, False)
        ]
        client.match_or_create_roles_from_names = (
            lambda *args, **kwargs: matched_roles
        )
        # when
        result = client.match_or_create_roles_from_names_2(
            TEST_GUILD_ID, ['alpha', 'bravo']
        )
        # then
        self.assertEqual(result, RolesSet([role_a, role_b]))

    def test_should_return_empty_roles(self):
        # given
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        client.match_or_create_roles_from_names = (
            lambda *args, **kwargs: []
        )
        # when
        result = client.match_or_create_roles_from_names_2(TEST_GUILD_ID, [])
        # then
        self.assertEqual(result, RolesSet([]))


class TestApiRequestBasics(NoSocketsTestCase):

    def setUp(self):
        self.client = DiscordClient(TEST_BOT_TOKEN, mock_redis)

    @patch(MODULE_PATH + '.requests', spec=requests)
    def test_raises_exception_on_invalid_method(self, mock_requests):
        with self.assertRaises(ValueError):
            self.client._api_request('xxx', 'users/@me')


@patch(MODULE_PATH + '.DiscordClient._redis_decr_or_set', spec=True)
@requests_mock.Mocker()
class TestRateLimitMechanic(NoSocketsTestCase):

    my_role_api = create_discord_role_object(1, "alpha")
    my_role_obj = create_role(id=1, name="alpha")

    @staticmethod
    def my_redis_pttl(name: str):
        if name == DiscordClient._KEY_GLOBAL_BACKOFF_UNTIL:
            return -1
        return TEST_RETRY_AFTER

    def test_proceed_if_requests_remaining(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        my_mock_redis = MagicMock(**{'pttl.side_effect': self.my_redis_pttl})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)

    @patch(MODULE_PATH + '.sleep', spec=True)
    def test_wait_if_reset_happens_soon(
        self, requests_mocker, mock_sleep, mock_redis_decr_or_set
    ):
        counter = 0

        def my_redis_pttl_2(name: str):
            if name == DiscordClient._KEY_GLOBAL_BACKOFF_UNTIL:
                return -1
            else:
                return 100

        def my_redis_decr_or_set(**kwargs):
            nonlocal counter
            counter += 1

            if counter < 2:
                return -1
            else:
                return 5

        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        mock_sleep.side_effect = my_sleep
        my_mock_redis = MagicMock(**{'pttl.side_effect': my_redis_pttl_2})
        mock_redis_decr_or_set.side_effect = my_redis_decr_or_set
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)

        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)
        self.assertTrue(mock_sleep.called)

    @patch(MODULE_PATH + '.sleep', spec=True)
    def test_wait_if_reset_happens_soon_and_sleep_must_not_be_negative(
        self, requests_mocker, mock_sleep, mock_redis_decr_or_set
    ):
        counter = 0

        def my_redis_pttl_2(name: str):
            if name == DiscordClient._KEY_GLOBAL_BACKOFF_UNTIL:
                return -1
            else:
                return -1

        def my_redis_decr_or_set(**kwargs):
            nonlocal counter
            counter += 1

            if counter < 2:
                return -1
            else:
                return 5

        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        mock_sleep.side_effect = my_sleep
        my_mock_redis = MagicMock(**{'pttl.side_effect': my_redis_pttl_2})
        mock_redis_decr_or_set.side_effect = my_redis_decr_or_set
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)

        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)
        self.assertTrue(mock_sleep.called)

    def test_throw_exception_if_rate_limit_reached(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        my_mock_redis = MagicMock(**{'pttl.side_effect': self.my_redis_pttl})
        mock_redis_decr_or_set.return_value = -1
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        try:
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
            )
        except Exception as ex:
            self.assertIsInstance(ex, DiscordRateLimitExhausted)
            self.assertEqual(ex.retry_after, TEST_RETRY_AFTER)

    @patch(MODULE_PATH + '.RATE_LIMIT_RETRIES', 1)
    @patch(MODULE_PATH + '.sleep', spec=True)
    def test_throw_exception_if_retries_are_exhausted(
        self, requests_mocker, mock_sleep, mock_redis_decr_or_set
    ):
        def my_redis_pttl_2(name: str):
            if name == DiscordClient._KEY_GLOBAL_BACKOFF_UNTIL:
                return -1
            return 100

        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        mock_sleep.side_effect = my_sleep
        my_mock_redis = MagicMock(**{'pttl.side_effect': my_redis_pttl_2})
        mock_redis_decr_or_set.return_value = -1
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)

        with self.assertRaises(RuntimeError):
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
            )

    def test_report_api_rate_limits(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        headers = {
            'x-ratelimit-limit': '10',
            'x-ratelimit-remaining': '9',
            'x-ratelimit-reset-after': '10.000',
        }
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            json=self.my_role_api,
            headers=headers
        )
        my_mock_redis = MagicMock(**{'pttl.side_effect': self.my_redis_pttl})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)

    def test_dont_report_api_rate_limits(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        headers = {
            'x-ratelimit-limit': '10',
            'x-ratelimit-remaining': '5',
            'x-ratelimit-reset-after': '10.000',
        }
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            json=self.my_role_api,
            headers=headers
        )
        my_mock_redis = MagicMock(**{'pttl.side_effect': self.my_redis_pttl})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)

    def test_ignore_errors_in_api_rate_limits(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        headers = {
            'x-ratelimit-limit': '10',
            'x-ratelimit-remaining': '0',
            'x-ratelimit-reset-after': 'invalid',
        }
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            json=self.my_role_api,
            headers=headers
        )
        my_mock_redis = MagicMock(**{'pttl.side_effect': self.my_redis_pttl})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)

    @patch(MODULE_PATH + '.DiscordClient._ensure_rate_limed_not_exhausted', spec=True)
    def test_can_turn_off_rate_limiting(
        self,
        requests_mocker,
        mock_ensure_rate_limed_not_exhausted,
        mock_redis_decr_or_set
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis, is_rate_limited=False)
        result = client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name=self.my_role_api['name']
        )
        self.assertEqual(result, self.my_role_obj)
        self.assertFalse(mock_ensure_rate_limed_not_exhausted.called)


@patch(MODULE_PATH + '.DiscordClient._redis_decr_or_set', spec=True)
@requests_mock.Mocker()
class TestBackoffHandling(NoSocketsTestCase):

    my_role_api = create_discord_role_object(1, "alpha")
    my_role_obj = create_role(id=1, name="alpha")

    def test_dont_raise_exception_when_no_global_backoff(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        my_mock_redis = MagicMock(**{'pttl.return_value': -1})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        result = client.create_guild_role(guild_id=TEST_GUILD_ID, role_name='dummy')
        self.assertEqual(result, self.my_role_obj)

    def test_raise_exception_when_global_backoff_in_effect(
        self, mock_redis_decr_or_set, requests_mocker
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        retry_after = 1000
        my_mock_redis = MagicMock(**{'pttl.return_value': retry_after})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        try:
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name='dummy'
            )
        except Exception as ex:
            self.assertIsInstance(ex, DiscordTooManyRequestsError)
            self.assertEqual(ex.retry_after, retry_after)

    @patch(MODULE_PATH + '.sleep', spec=True)
    def test_just_wait_if_global_backoff_ends_soon(
        self, requests_mocker, mock_sleep, mock_redis_decr_or_set,
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles', json=self.my_role_api
        )
        retry_after = 50
        mock_sleep.side_effect = my_sleep
        my_mock_redis = MagicMock(**{'pttl.return_value': retry_after})
        mock_redis_decr_or_set.return_value = 5
        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        client.create_guild_role(
            guild_id=TEST_GUILD_ID, role_name='dummy'
        )
        result = client.create_guild_role(guild_id=TEST_GUILD_ID, role_name='dummy')
        self.assertEqual(result, self.my_role_obj)
        self.assertTrue(mock_sleep.called)

    @patch(MODULE_PATH + '.DiscordClient._redis_set_if_longer', spec=True)
    def test_raise_exception_if_api_returns_429(
        self, requests_mocker, mock_redis_set_if_longer, mock_redis_decr_or_set,
    ):
        retry_after = 5000
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            status_code=429,
            json={'retry_after': retry_after}
        )
        my_mock_redis = MagicMock(
            **{'pttl.side_effect': TestRateLimitMechanic.my_redis_pttl}
        )
        mock_redis_decr_or_set.return_value = 5

        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        try:
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name='dummy'
            )
        except Exception as ex:
            self.assertIsInstance(ex, DiscordTooManyRequestsError)
            self.assertEqual(ex.retry_after, retry_after + DURATION_CONTINGENCY)
            self.assertTrue(mock_redis_set_if_longer.called)
            _, kwargs = mock_redis_set_if_longer.call_args
            self.assertEqual(kwargs['px'], retry_after + DURATION_CONTINGENCY)

    @patch(MODULE_PATH + '.DiscordClient._redis_set_if_longer', spec=True)
    def test_raise_exception_if_api_returns_429_no_retry_info(
        self, requests_mocker, mock_redis_set_if_longer, mock_redis_decr_or_set,
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            status_code=429,
            json={}
        )
        my_mock_redis = MagicMock(
            **{'pttl.side_effect': TestRateLimitMechanic.my_redis_pttl}
        )
        mock_redis_decr_or_set.return_value = 5

        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        try:
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name='dummy'
            )
        except Exception as ex:
            self.assertIsInstance(ex, DiscordTooManyRequestsError)
            self.assertEqual(ex.retry_after, DEFAULT_BACKOFF_DELAY)
            self.assertTrue(mock_redis_set_if_longer.called)
            _, kwargs = mock_redis_set_if_longer.call_args
            self.assertEqual(kwargs['px'], DEFAULT_BACKOFF_DELAY)

    @patch(MODULE_PATH + '.DiscordClient._redis_set_if_longer', spec=True)
    def test_raise_exception_if_api_returns_429_ignore_value_error(
        self, requests_mocker, mock_redis_set_if_longer, mock_redis_decr_or_set,
    ):
        requests_mocker.post(
            f'{API_BASE_URL}guilds/{TEST_GUILD_ID}/roles',
            status_code=429,
            json={'retry_after': "invalid"}
        )
        my_mock_redis = MagicMock(
            **{'pttl.side_effect': TestRateLimitMechanic.my_redis_pttl}
        )
        mock_redis_decr_or_set.return_value = 5

        client = DiscordClient(TEST_BOT_TOKEN, my_mock_redis)
        try:
            client.create_guild_role(
                guild_id=TEST_GUILD_ID, role_name='dummy'
            )
        except Exception as ex:
            self.assertIsInstance(ex, DiscordTooManyRequestsError)
            self.assertEqual(ex.retry_after, DEFAULT_BACKOFF_DELAY)
            self.assertTrue(mock_redis_set_if_longer.called)
            _, kwargs = mock_redis_set_if_longer.call_args
            self.assertEqual(kwargs['px'], DEFAULT_BACKOFF_DELAY)


class TestRedisDecode(NoSocketsTestCase):

    def test_decode_string(self):
        self.assertEqual(
            DiscordClient._redis_decode(b'MyTest123'), 'MyTest123'
        )

    def test_decode_bool(self):
        self.assertTrue(DiscordClient._redis_decode(True))
        self.assertFalse(DiscordClient._redis_decode(False))

    def test_decode_none(self):
        self.assertIsNone(DiscordClient._redis_decode(None))


class TestTouchLuaScripts(NoSocketsTestCase):

    def test__redis_script_decr_or_set(self):
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        client._redis_decr_or_set(name='dummy', value=5, px=1000)

    def test_redis_set_if_longer(self):
        client = DiscordClient(TEST_BOT_TOKEN, mock_redis)
        client._redis_set_if_longer(name='dummy', value=5, px=1000)
