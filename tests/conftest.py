from unittest.mock import patch, MagicMock
import pytest
import pytest_asyncio
import plugin
from .website_mock import BackendClientMock

from galaxy.api.consts import LicenseType
from galaxy.api.types import Game, LicenseInfo, LocalGame
from definitions import GameStatus, GameStatusTranslator, GameType

def _credentials():
    return {
        "ticket": "ticket",
        "sessionId": "session_id",
        "rememberMeTicket": "remember_me",
        "userId": "user_id",
        "username": "user_name",
        "refreshTime": "9999999999",
    }


class NewGame(object):
    def as_galaxy_game(self):
        passed_id = self.space_id if self.space_id else self.launch_id
        return Game(passed_id, self.name, [], LicenseInfo(LicenseType.SinglePurchase))

    def as_local_game(self):
        status = self.status if self.status is not None else GameStatus.Unknown
        if not self.space_id:
            return LocalGame(self.launch_id, GameStatusTranslator[status])
        else:
            return LocalGame(self.space_id, GameStatusTranslator[status])

    space_id: str = "123"
    launch_id: str = "321"
    install_id: str = "321"
    third_party_id: str = ""
    name: str = "UbisoftGame"
    path: str = ""
    type = GameType.New
    special_registry_path: str = ""
    exe: str = ""
    owned: bool = True
    considered_for_sending: bool = False
    status = GameStatus.NotInstalled

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

@pytest_asyncio.fixture
async def authenticated_plugin(create_plugin):
    plugin = create_plugin()
    await plugin.authenticate(_credentials())
    return plugin


@pytest.fixture
def create_authenticated_plugin(create_plugin):
    async def factory():
        plugin = create_plugin()
        await plugin.authenticate(_credentials())
        return plugin
    return factory