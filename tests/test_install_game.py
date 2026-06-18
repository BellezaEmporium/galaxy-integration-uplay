from unittest.mock import Mock, AsyncMock
import sys
import pytest_asyncio

from .conftest import NewGame
from definitions import GameStatus

if sys.platform == 'win32':
    @pytest_asyncio.fixture
    async def test_install_game_space_id(create_authenticated_plugin):
        pg = await create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = Mock(spec=pg.open_uplay_client)

        with Mock.patch("plugin.subprocess.Popen") as mock_popen:
            await pg.install_game("123")
            print("Popen call args:", mock_popen.call_args_list)
            mock_popen.assert_called_once_with("start uplay://install/321", shell=True)

        pg.open_uplay_client.assert_not_called()


    @pytest_asyncio.fixture
    async def test_install_game_launch_id(create_authenticated_plugin):
        pg = await create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = Mock(spec=pg.open_uplay_client)

        with Mock.patch("plugin.subprocess.Popen") as pop:
            await pg.install_game("321")
            pop.assert_called_with(f"start uplay://install/{new_game.launch_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    @pytest_asyncio.fixture
    async def test_install_game_game_installed(create_authenticated_plugin):
        pg = await create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = Mock(spec=pg.open_uplay_client)

        pg.launch_game = AsyncMock(return_value=None)

        with Mock.patch("plugin.subprocess.Popen") as pop:
            await pg.install_game("321")
            pop.assert_not_called()

        pg.launch_game.assert_called()


    @pytest_asyncio.fixture
    async def test_install_game_empty_collection(create_authenticated_plugin):
        pg = await create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = []

        pg.open_uplay_client = Mock(spec=pg.open_uplay_client)

        with Mock.patch("plugin.subprocess.Popen") as pop:
            await pg.install_game("321")
            pop.assert_not_called()

        pg.open_uplay_client.assert_called()


    @pytest_asyncio.fixture
    async def test_install_game_cant_perform(create_authenticated_plugin):
        pg = await create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = False

        pg.games_collection = [new_game]

        pg.open_uplay_client = Mock(spec=pg.open_uplay_client)

        with Mock.patch("plugin.subprocess.Popen") as pop:
            await pg.install_game("321")
            pop.assert_not_called()

        pg.open_uplay_client.assert_not_called()