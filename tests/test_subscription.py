import pytest
from .async_mock import AsyncMock
from galaxy.api.types import Subscription, SubscriptionGame, SubscriptionDiscovery
from galaxy.api.errors import BackendError


TEST_SUB_GAMES = [
    SubscriptionGame(game_title='game_a', game_id='123'),
    SubscriptionGame(game_title='game_b', game_id='321'),
    SubscriptionGame(game_title='game_c', game_id='231')]


SUBSCRIPTION_RESPONSE_OK = {
        'games': [{
            'id': 344,
            'name': 'game_a',
            'image': 'https://store.ubi.com/dw/image/v2/ABBS_PRD/on/demandware.static/-/Sites-masterCatalog/default/dw4b85c1f8/images/large/5d2628e65cdf9a0bf0481659.jauthenticated_plugin?sw=220&sh=440&sm=fit',
            'gameId': 5,
            'packageId': 14653,
            'uplayGameId': 123,
            'ownership': 1,
            'hasSavefilesAlert': True,
            'releaseDate': '2019-04-16',
            'brand': 'ANNO'
        }, {
            'id': 297,
            'name': 'game_b',
            'image': 'https://ubistatic2-a.akamaihd.net/webservicesteam/uplayplusvault/PROD/covers/Anno_2205.jauthenticated_plugin',
            'gameId': 7,
            'packageId': 14654,
            'uplayGameId': 321,
            'ownership': 0,
            'hasSavefilesAlert': True,
            'releaseDate': '2016-10-27',
            'brand': 'ANNO'
        }, {
            'id': 200,
            'name': "game_c",
            'image': 'https://ubistatic2-a.akamaihd.net/webservicesteam/uplayplusvault/PROD/covers/Assassins_Creed.png',
            'gameId': 10,
            'packageId': 13151,
            'uplayGameId': 231,
            'ownership': 0,
            'hasSavefilesAlert': False,
            'releaseDate': '2008-04-01',
            'brand': "ASSASSIN'S CREED"
        }]
    }


@pytest.mark.asyncio
async def test_subscription_not_owned(authenticated_plugin):
    authenticated_plugin.client.get_subscription = AsyncMock()
    authenticated_plugin.client.get_subscription.return_value = None

    sub_status = await authenticated_plugin.get_subscriptions()

    exp_result = [Subscription(subscription_name="Ubisoft+", end_time=None, owned=False,
                               subscription_discovery=SubscriptionDiscovery.AUTOMATIC)]

    assert sub_status == exp_result


@pytest.mark.asyncio
async def test_subscription_owned(authenticated_plugin):
    authenticated_plugin.client.get_subscription = AsyncMock()
    authenticated_plugin.client.get_subscription.return_value = SUBSCRIPTION_RESPONSE_OK

    sub_status = await authenticated_plugin.get_subscriptions()
    exp_result = [Subscription(subscription_name="Ubisoft+", owned=True, end_time=None,
                               subscription_discovery=SubscriptionDiscovery.AUTOMATIC)]

    assert sub_status == exp_result


@pytest.mark.asyncio
async def test_subscription_games_context_ok(authenticated_plugin):
    authenticated_plugin.client.get_subscription_games = AsyncMock(
        return_value=SUBSCRIPTION_RESPONSE_OK['games'])

    sub_games_list = await authenticated_plugin.prepare_subscription_games_context(['Uplay+'])

    exp_result = TEST_SUB_GAMES

    assert sub_games_list == exp_result

@pytest.mark.asyncio
async def test_subscription_games_context_not_owned(authenticated_plugin):
    authenticated_plugin.client.get_subscription_games = AsyncMock(return_value=None)

    sub_games_list = await authenticated_plugin.prepare_subscription_games_context(['Uplay+'])

    assert sub_games_list is None


@pytest.mark.asyncio
async def test_subscription_games_context_error(authenticated_plugin):
    authenticated_plugin.client.get_subscription_games = AsyncMock(side_effect=BackendError())

    with pytest.raises(BackendError):
        await authenticated_plugin.prepare_subscription_games_context(['Uplay+'])


@pytest.mark.asyncio
async def test_subscription_games(authenticated_plugin):
    authenticated_plugin.client.get_subscription = AsyncMock()
    authenticated_plugin.client.get_subscription.return_value = SUBSCRIPTION_RESPONSE_OK

    async for sub_games in authenticated_plugin.get_subscription_games('Uplay+', TEST_SUB_GAMES):
        result = sub_games

    exp_result = TEST_SUB_GAMES

    assert result == exp_result






