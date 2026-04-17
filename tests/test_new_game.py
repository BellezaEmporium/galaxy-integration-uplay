import asyncio
import unittest.mock as mock

from .conftest import NewGame


def test_new_game_owned(create_authenticated_plugin):
    loop = asyncio.get_event_loop()
    pg = create_authenticated_plugin()

    new_game = NewGame()

    pg.add_game = mock.MagicMock()

    loop.run_until_complete(pg._add_new_games([new_game]))

    pg.add_game.assert_called_with(new_game.as_galaxy_game())


def test_new_game_not_owned(create_authenticated_plugin):
    loop = asyncio.get_event_loop()
    pg = create_authenticated_plugin()

    new_game = NewGame()
    new_game.owned = False

    loop.run_until_complete(pg._add_new_games([new_game]))

    pg.add_game.assert_not_called()


def test_new_game_empty_list(create_authenticated_plugin):
    loop = asyncio.get_event_loop()
    pg = create_authenticated_plugin()

    loop.run_until_complete(pg._add_new_games([]))

    pg.add_game.assert_not_called()
