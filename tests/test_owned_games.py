import asyncio
import json
from unittest.mock import Mock

import pytest
from galaxy.api.consts import LicenseType
from galaxy.api.types import Game, LicenseInfo
from galaxy.unittest.mock import AsyncMock

from src.definitions import UbisoftGame, GameType, GameStatus


@pytest.fixture
def result_owned_ubiplus_games():
    data = json.loads('''{"jsonrpc": "2.0", "id": "3", "result": {"owned_games": [{"game_id": "6678eff0-1293-4f87-8c8c-06a4ca646068", "game_title": "Assassin's Creed\u00ae Unity", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}, {"game_id": "f40e304d-8e8d-4343-8270-d06487c35add", "game_title": "Far Cry\u00ae 5", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}, {"game_id": "6edd234a-abff-4e90-9aab-b9b9c6e49ff7", "game_title": "Tom Clancy's The Division\u2122 ", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}, {"game_id": "1d1273d9-2120-4e55-8d98-66e08781258e", "game_title": "Trackmania Turbo", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}, {"game_id": "50228b8c-bbaa-4c32-83c6-2831a1ac317c", "game_title": "Far Cry\u00ae 3", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}, {"game_id": "4bd0476b-acec-446d-b526-23a0209101ca", "game_title": "Far Cry\u00ae 3 Blood Dragon", "dlcs": [], "license_info": {"license_type": "SinglePurchase"}}]}}\n''')
    return [
        Game(
            game['game_id'],
            game['game_title'],
            [],
            LicenseInfo(LicenseType.SinglePurchase)
        ) for game in data['result']['owned_games']
    ]


def test_owned_games_ubiplus_only(create_authenticated_plugin, result_owned_ubiplus_games):
    loop = asyncio.get_event_loop()
    pg = create_authenticated_plugin()

    result = loop.run_until_complete(pg.get_owned_games())
    assert result == result_owned_ubiplus_games


@pytest.mark.parametrize("response", [
    {"data": {}},
    {},
    "BAD_RESPONSE",
    None,
])
@pytest.mark.asyncio
async def test_owned_games_with_unknown_response_from_ubiplus_games(authenticated_plugin, backend_client, response):
    backend_client.get_entitlements = AsyncMock(return_value=response)
    owned_game_from_ownership_file = UbisoftGame(
        space_id='',
        launch_id="GAME_ID",
        install_id=Mock(str),
        third_party_id='',
        name="GAME_TITLE",
        path='',
        type=GameType.New,
        special_registry_path='',
        exe='',
        status=GameStatus.Unknown,
        owned=True,
        activation_id=Mock(str)
    )
    authenticated_plugin.games_collection = [owned_game_from_ownership_file]

    result = await authenticated_plugin.get_owned_games()

    assert result == [Game("GAME_ID", "GAME_TITLE", [], LicenseInfo(LicenseType.SinglePurchase))]


@pytest.mark.parametrize("type", [
    ("PC", "STADIA", "STADIA"),
    ("STADIA", "PC", "STADIA"),
    ("STADIA", "STADIA", "PC"),
])
def test_owned_games_ubiplus_only_with_multi_platform_groups(create_authenticated_plugin, backend_client, type):
    loop = asyncio.get_event_loop()
    pg = create_authenticated_plugin()
    data = {
            "data": {
                "viewer": {
                  "id": "57a84edf-09d7-448f-a18f-09c504b84637",
                  "ownedGames": {
                    "totalCount": 8,
                    "nodes": [
                      {
                        "id": "6678eff0-1293-4f87-8c8c-06a4ca646068",
                        "spaceId": "6678eff0-1293-4f87-8c8c-06a4ca646068",
                        "name": "Assassin's Creed\u00ae Unity",
                        "viewer": {
                          "meta": {
                            "id": "57a84edf-09d7-448f-a18f-09c504b84637-8c8d9b22-498c-45e6-80da-7cd22787c9b3",
                            "ownedPlatformGroups": [
                              [
                                {
                                  "id": "35c5c607-2717-47d9-9323-7df47c6e1c4d",
                                  "type": type[0]
                                },
                                {
                                  "id": "35c5c607-2717-47d9-9323-7df47c6e1c4d",
                                  "type": type[1]
                                },
                              ],
                              [
                                {
                                  "id": "35c5c607-2717-47d9-9323-7df47c6e1c4d",
                                  "type": type[2]
                                },
                              ],
                            ]
                          }
                        }
                      },
                    ]
                  }
                }
            }
        }
    backend_client.get_entitlements = AsyncMock(return_value=data)
    expected_result = [Game(
        "6678eff0-1293-4f87-8c8c-06a4ca646068",
        "Assassin's Creed\u00ae Unity",
        [],
        LicenseInfo(LicenseType.SinglePurchase)
    )]

    result = loop.run_until_complete(pg.get_owned_games())
    assert result == expected_result


@pytest.mark.asyncio
async def test_owned_games_with_null_meta_in_viewer_ubiplus_games_response(authenticated_plugin, backend_client):
    data = {
        "data": {
            "viewer": {
                "id": "57a84edf-09d7-448f-a18f-09c504b84637",
                "ownedGames": {
                    "totalCount": 1,
                    "nodes": [
                        {
                            "id": "GAME_ID_1",
                            "spaceId": "GAME_ID_1",
                            "name": "GAME_1",
                            "viewer": {
                                "meta": None
                            }
                        },
                        {
                            "id": "GAME_ID_2",
                            "spaceId": "GAME_ID_2",
                            "name": "GAME_2",
                            "viewer": None
                        },
                        {
                            "id": "GAME_ID_3",
                            "spaceId": "GAME_ID_3",
                            "name": "GAME_3",
                            "viewer": {
                                "meta": {
                                    "ownedPlatformGroups": [
                                        [
                                            {
                                              "id": "35c5c607-2717-47d9-9323-7df47c6e1c4d",
                                              "type": "PC"
                                            },
                                        ],
                                    ]
                                }
                            }
                        },
                    ]
                }
            }
        }
    }
    backend_client.get_ubiplus_titles = AsyncMock(return_value=data)
    expected_result = [Game(
        "GAME_ID_3",
        "GAME_3",
        [],
        LicenseInfo(LicenseType.SinglePurchase)
    )]

    result = await authenticated_plugin.get_owned_games()

    assert result == expected_result
