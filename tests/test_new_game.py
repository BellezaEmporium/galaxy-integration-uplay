import unittest.mock as mock
import pytest_asyncio

from .conftest import NewGame


@pytest_asyncio.fixture
async def test_new_game_owned(create_authenticated_plugin):
    pg = await create_authenticated_plugin()

    new_game = NewGame()

    pg.add_game = mock.MagicMock()

    await pg._add_new_games([new_game])

    pg.add_game.assert_called_with(new_game.as_galaxy_game())


@pytest_asyncio.fixture
async def test_new_game_not_owned(create_authenticated_plugin):
    pg = await create_authenticated_plugin()

    new_game = NewGame()
    new_game.owned = False

    await pg._add_new_games([new_game])

    pg.add_game.assert_not_called()


@pytest_asyncio.fixture
async def test_new_game_empty_list(create_authenticated_plugin):
    pg = await create_authenticated_plugin()

    await pg._add_new_games([])

    pg.add_game.assert_not_called()
