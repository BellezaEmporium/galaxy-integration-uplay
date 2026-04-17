import pytest
from unittest.mock import Mock, MagicMock
from .async_mock import AsyncMock

from galaxy.api.types import GameTime
from galaxy.api.errors import BackendNotAvailable
from games_collection import GamesCollection


class MockUbisoftGame():
    def __init__(self, space_id, launch_id=None, install_id=None):
        self.space_id = space_id
        self.launch_id = launch_id
        self.install_id = install_id
        self.name = Mock()


@pytest.fixture
def _patch_plugin(mocker, authenticated_plugin):
    def func(game_times):
        authenticated_plugin.game_time_import_failure = MagicMock(spec=())
        authenticated_plugin.game_time_import_success = MagicMock(spec=())
        # defaults to be overwritten for specific test if needed
        authenticated_plugin.client.get_game_stats = AsyncMock(return_value={'Statscards': []})

        collection = GamesCollection()
        collection.extend([MockUbisoftGame(gt.game_id) for gt in game_times])
        authenticated_plugin.games_collection = collection

        mocker.patch('plugin.find_times', autospec=True, side_effect=[
            (gt.time_played, gt.last_played_time)
            for gt in game_times
        ])
        return authenticated_plugin
    return func


@pytest.mark.asyncio
async def test_game_times_variants(_patch_plugin):
    game_times = [  # expected results
        GameTime('121', None, 1553169680),
        GameTime('122', 1312, None),
        GameTime('133', None, None),
        GameTime('144', 2434, 1553439634),
    ]
    plugin = _patch_plugin(game_times)
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])
    assert context == {
        "121": GameTime(game_id="121", time_played=None, last_played_time=1553169680),
        "122": GameTime(game_id="122", time_played=1312, last_played_time=None),
        "133": GameTime(game_id="133", time_played=None, last_played_time=None),
        "144": GameTime(game_id="144", time_played=2434, last_played_time=1553439634)
    }      
    

@pytest.mark.asyncio
async def test_game_has_no_statscards(_patch_plugin):
    game_time = GameTime('121', None, None)
    plugin = _patch_plugin([game_time])
    plugin.client.get_game_stats = AsyncMock(return_value={})
    context = await plugin.prepare_game_times_context([game_time.game_id])
    
    assert context == {
    "121": GameTime(game_id="121", time_played=None, last_played_time=None)
    }
    

@pytest.mark.asyncio
async def test_backend_error(_patch_plugin):
    game_id = '121'
    error = BackendNotAvailable()
    game_times = [GameTime(game_id, None, None)]

    plugin = _patch_plugin(game_times)
    plugin.client.get_game_stats = AsyncMock(side_effect=error)
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])
    
    assert context == {}


@pytest.mark.asyncio
async def test_ask_for_space_id(_patch_plugin):
    """Situation when backend ask for game using spaceId, and we know space_id and launch_id"""
    space_id, launch_id = 'adsdf-2323e2-sdfasdf-11231', '555'
    gog_backend_id = space_id
    game_times = [GameTime(gog_backend_id, 231, 1553169680)]

    plugin = _patch_plugin(game_times)
    plugin.games_collection = GamesCollection([MockUbisoftGame(space_id, launch_id)])
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])

    assert context == {
    "adsdf-2323e2-sdfasdf-11231": GameTime(game_id="adsdf-2323e2-sdfasdf-11231", time_played=231, last_played_time=1553169680)
    }


@pytest.mark.asyncio
async def test_ask_for_launch_id(_patch_plugin):
    """Situation when backend ask for game using launch_id, and we know space_id and launch_id"""
    space_id, launch_id = 'adsdf-2323e2-sdfasdf-11231', '555'
    gog_backend_id = launch_id
    game_times = [GameTime(gog_backend_id, 231, 1553169680)]

    plugin = _patch_plugin(game_times)
    plugin.games_collection = GamesCollection([MockUbisoftGame(space_id, launch_id)])
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])
    
    assert context == {
    "555": GameTime(game_id="555", time_played=231, last_played_time=1553169680)
    }


@pytest.mark.asyncio
async def test_game_not_in_games_collection(_patch_plugin):
    gog_backend_id = 'adsdf-2323e2-sdfasdf-11231'
    game_times = [GameTime(gog_backend_id, 231, 1553169680)]

    plugin = _patch_plugin(game_times)
    plugin.games_collection = GamesCollection()
    context = await plugin.prepare_game_times_context([gog_backend_id])
    
    assert context == {}


@pytest.mark.asyncio
async def test_cache(mocker, _patch_plugin):
    game_times = [
        GameTime('121', None, None),  # no stats - go to cache
    ]
    # mock
    plugin = _patch_plugin(game_times)
    plugin.client.get_game_stats = AsyncMock(return_value={})
    plugin.games_collection = MagicMock()
    # import stats first time
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])
    
    assert context == {
    "121": GameTime(game_id="121", time_played=None, last_played_time=None)
    }
    
    # refresh mocks
    mocker.stopall()
    plugin = _patch_plugin(game_times)
    plugin.client.get_game_stats = AsyncMock(return_value={})
    plugin.games_collection = MagicMock()
    plugin.games_collection.get.return_value = None
    plugin.get_owned_games = AsyncMock()
    # import stats second time
    context = await plugin.prepare_game_times_context([gt.game_id for gt in game_times])
    
    assert context == {
    "121": GameTime(game_id="121", time_played=None, last_played_time=None)
    }
    plugin.get_owned_games.assert_called()
    