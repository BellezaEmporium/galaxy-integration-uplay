import asyncio
import unittest.mock as mock
import sys

from .conftest import NewGame
from .async_mock import AsyncMock
from definitions import GameStatus

if sys.platform == 'win32':
    def test_install_game_space_id(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as mock_popen:
            loop.run_until_complete(pg.install_game("123"))
            print("Popen call args:", mock_popen.call_args_list)
            mock_popen.assert_called_once_with("start uplay://install/321", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_install_game_launch_id(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.install_game("321"))
            pop.assert_called_with(f"start uplay://install/{new_game.launch_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_install_game_game_installed(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = [new_game]

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        pg.launch_game = AsyncMock(return_value=None)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.install_game("321"))
            pop.assert_not_called()

        pg.launch_game.assert_called()


    def test_install_game_empty_collection(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = []

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.install_game("321"))
            pop.assert_not_called()

        pg.open_uplay_client.assert_called()


    def test_install_game_cant_perform(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.NotInstalled

        pg.user_can_perform_actions.return_value = False

        pg.games_collection = [new_game]

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.install_game("321"))
            pop.assert_not_called()

        pg.open_uplay_client.assert_not_called()