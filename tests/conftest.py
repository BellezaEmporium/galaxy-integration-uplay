import asyncio
from unittest.mock import patch, MagicMock
import pytest
import src.plugin as plugin
from tests.website_mock import BackendClientMock

from galaxy.api.consts import LicenseType
from galaxy.api.types import Game, LicenseInfo

class NewGame(object):
    def as_galaxy_game(self):
        passed_id = self.space_id if self.space_id else self.launch_id
        return Game(passed_id, self.name, [], LicenseInfo(LicenseType.SinglePurchase))

    space_id: str = "123"
    launch_id: str = "321"
    install_id: str = "321"
    third_party_id: str = ""
    name: str = "UbiGame"
    path: str = ""
    type: str = "New"
    special_registry_path: str = ""
    exe: str = ""
    owned: bool = True
    considered_for_sending: bool = False
    status: str = "NotInstalled"

@pytest.fixture()
def local_client():
    mock = MagicMock()
    mock.was_user_logged_in = False
    mock.ownership_accessible.return_value = False
    mock.configurations_accessible.return_value = False
    return mock


@pytest.fixture()
def backend_client():
    return BackendClientMock()


@pytest.fixture()
def create_plugin(local_client, backend_client):
    def function():
        with patch("plugin.LocalClient", return_value=local_client):
            with patch("plugin.BackendClient", return_value=backend_client):
                return plugin.UplayPlugin(MagicMock(), MagicMock(), None)
    return function


@pytest.fixture()
def create_authenticated_plugin(create_plugin):

    def function():
        loop = asyncio.get_event_loop()

        pg = create_plugin()
        pg.user_can_perform_actions = MagicMock()
        pg.games_collection.get_local_games = MagicMock()
        pg._game_ownership_is_glitched = MagicMock()
        pg.add_game = MagicMock()

        credentials = {
            "cookie_jar": "COOKIE_JAR",
            "access_token": "ACCESS_TOKEN"}
        loop.run_until_complete(pg.authenticate(credentials))

        return pg

    return function


@pytest.fixture()
def authenticated_plugin(create_authenticated_plugin):
    return create_authenticated_plugin()
