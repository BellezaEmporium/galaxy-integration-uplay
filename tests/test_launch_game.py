import asyncio
import unittest.mock as mock
import sys

from .conftest import NewGame
from definitions import GameStatus, GameType
from games_collection import GamesCollection

if sys.platform == 'win32':
    def test_launch_game_space_id(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = GamesCollection()
        pg.games_collection.extend([new_game])

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.launch_game("123"))
            pop.assert_called_with(f"start uplay://launch/{new_game.launch_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_launch_game_launch_id(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = GamesCollection()
        pg.games_collection.extend([new_game])

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.launch_game("321"))
            pop.assert_called_with(f"start uplay://launch/{new_game.launch_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_launch_game_not_installed(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = GamesCollection()
        pg.games_collection.extend([new_game])

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.subprocess.Popen") as pop:
            loop.run_until_complete(pg.launch_game("321"))
            pop.assert_called_with(f"start uplay://install/{new_game.install_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_launch_steam_game(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.type = GameType.Steam
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = GamesCollection()
        pg.games_collection.extend([new_game])

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.is_steam_installed") as steam_installed:
            with mock.patch("plugin.subprocess.Popen") as pop:
                steam_installed.return_value = True
                loop.run_until_complete(pg.launch_game("321"))
                pop.assert_called_with(f"start steam://rungameid/{new_game.third_party_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


    def test_launch_steam_game_steam_not_installed(create_authenticated_plugin):
        loop = asyncio.get_event_loop()
        pg = create_authenticated_plugin()

        new_game = NewGame()
        new_game.type = GameType.Steam
        new_game.status = GameStatus.Installed

        pg.user_can_perform_actions.return_value = True

        pg.games_collection = GamesCollection()
        pg.games_collection.extend([new_game])

        pg.open_uplay_client = mock.create_autospec(pg.open_uplay_client)

        with mock.patch("plugin.is_steam_installed") as steam_installed:
            with mock.patch("plugin.subprocess.Popen") as pop:
                steam_installed.return_value = False
                loop.run_until_complete(pg.launch_game("321"))
                pop.assert_called_with(f"start uplay://open/game/{new_game.launch_id}", shell=True)

        pg.open_uplay_client.assert_not_called()


