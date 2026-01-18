import asyncio
import json
import time
import logging as log
import multiprocessing
import subprocess
import sys
import webbrowser
import aiohttp
from yaml import scanner
from urllib.parse import unquote
from typing import Any, List, AsyncGenerator, Optional


from galaxy.api.consts import Platform
from galaxy.api.jsonrpc import ApplicationError
from galaxy.api.errors import InvalidCredentials, AuthenticationRequired, AccessDenied, UnknownError, \
    UnknownBackendResponse
from galaxy.api.plugin import Plugin, create_and_run_plugin
from galaxy.api.types import Authentication, GameTime, NextStep, FriendInfo, GameLibrarySettings, \
    SubscriptionGame, Subscription, SubscriptionDiscovery

from backend import BackendClient
from local_client import LocalClient
from local_file_parser import LocalParser
from local_game_status import ProcessWatcher, GameStatusNotifier
from local_helper import get_local_game_path, get_size_at_path
from definitions import GameStatus, UbisoftGame, GameType, System, SYSTEM
from stats import find_times
from consts import AUTH_JS, UBISOFT_APPID, UBISOFT_GENOMEID
from games_collection import GamesCollection
from version import __version__
from steam import is_steam_installed

if SYSTEM == System.WINDOWS:
    import ctypes


class UplayPlugin(Plugin):
    def __init__(self, reader, writer, token):
        super().__init__(Platform.Uplay, __version__, reader, writer, token)
        self.client = BackendClient(self)
        self.local_client = LocalClient()
        self.cached_game_statuses = {}
        self.games_collection = GamesCollection()
        self.process_watcher = ProcessWatcher()
        self.game_status_notifier = GameStatusNotifier(self.process_watcher)
        self.tick_count = 0
        self.updating_games = False
        self.owned_games_sent = False
        self.parsing_ubiplus_games = False
        self.parsed_local_games = False
        self._last_successful_auth = None

    def auth_lost(self):
        self.lost_authentication()

    async def authenticate(self, stored_credentials=None):
        """Called when the plugin is started and needs to authenticate the user"""

        params = {
            "window_title": "Login | Ubisoft WebAuth",
            "window_width": 460,
            "window_height": 690,
            "start_uri": f"https://connect.ubisoft.com/login?appId={UBISOFT_APPID}&genomeId={UBISOFT_GENOMEID}&lang=en-US&nextUrl=https:%2F%2Fconnect.ubisoft.com%2Fready",
            "end_uri_regex": r".*rememberMeTicket.*"
        }
        if not stored_credentials:
            return NextStep("web_session", params, js=AUTH_JS)
        try:
            user_data = await self.client.authorise_with_stored_credentials(stored_credentials)
        except (AccessDenied, AuthenticationRequired):
            raise InvalidCredentials()
        except Exception:
            return NextStep("web_session", params, js=AUTH_JS)
        
        if not isinstance(user_data, AuthenticationRequired):
            self.local_client.initialize(user_data['userId'])
            self.client.set_auth_lost_callback(self.auth_lost)
            auth = Authentication(user_data.get('userId') or '', user_data.get('username') or '')
            self._last_successful_auth = time.time()
            return auth
        else:
            return NextStep("web_session", params, js=AUTH_JS)

    async def pass_login_credentials(self, step, credentials, cookies):
        """Called just after CEF authentication (called as NextStep by authenticate)"""
        url = credentials["end_uri"][len("https://connect.ubisoft.com/change_domain/"):]
        storage_jsons = json.loads("[" + unquote(url) + "]")
        user_data = await self.client.authorise_with_local_storage(storage_jsons)
        self.local_client.initialize(user_data['userId'])
        self.client.set_auth_lost_callback(self.auth_lost)
        auth = Authentication(user_data.get('userId') or '', user_data.get('username') or '')
        self._last_successful_auth = time.time()
        return auth

    async def get_owned_games(self):
        if not self.client.is_authenticated():
            raise AuthenticationRequired()

        if SYSTEM == System.WINDOWS:
            self._parse_local_games()
            self._parse_local_game_ownership()

        try:
            await self._parse_ubiplus_games()
        except Exception as e:
            log.exception(f"Parsing ubiplus games failed: {repr(e)}")

        try:
            await self._parse_subscription_games()
        except Exception as e:
            log.warning(f"Parsing subscriptions failed, most likely account without subscription {repr(e)}")

        self.owned_games_sent = True

        for game in self.games_collection:
            game.considered_for_sending = True

        return [game.as_galaxy_game() for game in self.games_collection
                if game.owned]

    async def _parse_subscription_games(self):
        """Parse Ubisoft+ subscription games list (vault)"""
        try:
            games_data = await self.client.get_subscription_games()
            if not games_data:
                return
            # games_data is a list of product dicts
            parsed = []
            for prod in games_data:
                try:
                    launch_id = str(prod.get('ubisoftConnectGameId') or prod.get('uplayGameId') or '')
                    if not launch_id:
                        continue
                    parsed.append(UbisoftGame(space_id='', launch_id=launch_id, install_id=launch_id,
                                             third_party_id='', name=prod.get('name') or prod.get('title') or 'Unknown',
                                             path='', type=GameType.New, special_registry_path='', exe='',
                                             status=GameStatus.Unknown, owned=True,
                                             activation_id=str(prod.get('id') or '')))
                except Exception as e:
                    log.debug(f"Skip subscription product parse error: {repr(e)}")
            if parsed:
                self.games_collection.extend(parsed)
        except Exception as e:
            log.debug(f"Subscription games parsing failed: {repr(e)}")

    async def _parse_ubiplus_games(self):
        """Parse owned games list from backend"""
        BATCH_SIZE = 50  # Ubisoft can only return 50 results per request. Do not overload.

        if not self.parsing_ubiplus_games:
            try:
                self.parsing_ubiplus_games = True
                data = await self.client.get_entitlements()
                entitlements_data = data.get('entitlements', [])
                log.debug(f"Processing {len(entitlements_data)} total entitlements")
                games = []
                for game in entitlements_data:
                    try:
                        if game.get('accessLevel') == 'owned' and game.get('type') == 'game' and game.get("availability") != 'expired':
                            games.append(game)
                    except Exception as e:
                        log.warning(f"Error processing entitlement: {e}")
                        continue
                log.debug(f"Filtered {len(games)} owned games from {len(entitlements_data)} total entitlements")
                
                ubiplus_games = []
                batched_games = [games[i:i + BATCH_SIZE] for i in range(0, len(games), BATCH_SIZE)]
                log.debug(f"Processing {len(batched_games)} batches of up to {BATCH_SIZE} games each")
                
                for batch_index, game_batch in enumerate(batched_games):
                    try:
                        space_ids = [game['spaceId'] for game in game_batch if game.get('spaceId')]
                        if not space_ids:
                            log.debug(f"Batch {batch_index + 1}: No valid spaceIds, skipping")
                            continue
                            
                        log.debug(f"Batch {batch_index + 1}/{len(batched_games)}: Requesting {len(space_ids)} games")
                        game_request = await self.client.get_applications(space_ids)
                        game_data = game_request.get('games', [])
                        log.debug(f"Batch {batch_index + 1}: Received {len(game_data)} games from API")
                        
                        for game in game_data:
                            try:
                                platforms = game.get('platforms', [])
                                pc_platform_exists = any(
                                    platform.get('type') == "PC" 
                                    for platform in platforms 
                                    if isinstance(platform, dict)
                                )
                                if pc_platform_exists:
                                    ubiplus_games.append(UbisoftGame(
                                        space_id=game.get('spaceId', ''),
                                        launch_id='', install_id='', third_party_id='',
                                        name=game.get('name', 'Unknown'), path='', type=GameType.New,
                                        special_registry_path='', exe='',
                                        status=GameStatus.Unknown, owned=True
                                    ))
                            except Exception as e:
                                log.warning(f"Error processing game data: {e}")
                    except TypeError as e:
                        log.warning(f"Batch {batch_index + 1}: TypeError - {e}")
                        continue
                    except Exception as e:
                        log.warning(f"Batch {batch_index + 1}: Error - {repr(e)}")
                        continue
                
                log.info(f"Parsed {len(ubiplus_games)} PC games from Ubisoft entitlements")
                self.games_collection.extend(ubiplus_games)
            except (KeyError, TypeError) as e:
                log.error(f"Unknown response from Ubisoft while trying to parse games {repr(e)}")
                raise UnknownBackendResponse()
            except ApplicationError as e:
                log.error(f"Encountered exception while parsing Ubisoft games {repr(e)}")
                raise e
            except Exception as e:
                log.error(f"Encountered exception while parsing Ubisoft games {repr(e)}")
            finally:
                self.parsing_ubiplus_games = False
        else:
            while self.parsing_ubiplus_games:
                await asyncio.sleep(0.2)

    def _parse_local_games(self):
        """Parsing local files should lead to every game having a launch id.
        A game in the games_collection which doesn't have a launch id probably
        means that a game was added through the get_entitlements request but its space id
        was not present in configuration file and we couldn't find a matching launch id for it."""
        if self.local_client.configurations_accessible():
            try:
                configuration_data = self.local_client.read_config()
                p = LocalParser()
                games = []
                for game in p.parse_games(configuration_data):
                    games.append(game)
                self.games_collection.extend(games)
            except scanner.ScannerError as e:
                log.error(f"Scanner error while parsing configuration, yaml is probably corrupted {repr(e)}")

    def _parse_local_game_ownership(self):
        if self.local_client.ownership_accessible():
            ownership_data = self.local_client.read_ownership()
            p = LocalParser()
            ownership_records = p.get_owned_local_games(ownership_data)
            log.info(f"Ownership Records {ownership_records}")
            for game in self.games_collection:
                if game.install_id:
                    if int(game.install_id) in ownership_records:
                        game.owned = True
                if game.launch_id:
                    if int(game.launch_id) in ownership_records:
                        game.owned = True

    def _update_games(self):
        self.updating_games = True
        self._parse_local_games()
        self._parse_local_game_ownership()
        self.updating_games = False

    def _update_local_games_status(self):
        cached_statuses = self.cached_game_statuses
        if cached_statuses is None:
            return

        for game in self.games_collection:
            try:
                self.game_status_notifier.update_game(game)
                if game.status != cached_statuses[game.install_id]:
                    log.info(f"Game {game.name} path changed: updating status from {cached_statuses[game.install_id]} to {game.status}")
                    self.update_local_game_status(game.as_local_game())
                    self.cached_game_statuses[game.install_id] = game.status
            except KeyError:
                self.game_status_notifier.update_game(game)
                ''' If a game wasn't previously in a cache then and it appears with an installed or running status
                 it most likely means that client was just installed '''
                if game.status in [GameStatus.Installed, GameStatus.Running]:
                    self.update_local_game_status(game.as_local_game())
                self.cached_game_statuses[game.install_id] = game.status

    if SYSTEM == System.WINDOWS:
        async def get_local_games(self):
            self._parse_local_games()

            local_games = []

            for game in self.games_collection:
                self.cached_game_statuses[game.launch_id] = game.status
                if game.status == GameStatus.Installed or game.status == GameStatus.Running:
                    local_games.append(game.as_local_game())
            self._update_local_games_status()
            self.parsed_local_games = True
            return local_games

    async def _add_new_games(self, games):
        await self._parse_ubiplus_games()
        self._parse_local_game_ownership()
        for game in games:
            if game.owned:
                self.add_game(game.as_galaxy_game())

    async def prepare_game_times_context(self, game_ids):
        return await self.get_playtime(game_ids)

    async def get_game_time(self, game_id, context):
        game_time = context.get(game_id)
        if game_time is None:
            raise UnknownError("Game {} not owned".format(game_id))
        return game_time

    async def get_playtime(self, game_ids):
        if not self.client.is_authenticated():
            raise AuthenticationRequired()

        games_playtime = {}
        blacklist = json.loads(self.persistent_cache.get('games_without_stats', '{}'))
        current_time = int(time.time())

        for game_id in game_ids:
            if not self.games_collection.get(game_id):
                await self.get_owned_games()
                break

        for game_id in game_ids:
            try:
                expire_in = blacklist.get(game_id, 0) - current_time
                if expire_in > 0:
                    log.debug(f'Cache: No game stats for {game_id}. Recheck in {expire_in}s')
                    games_playtime[game_id] = GameTime(game_id, None, None)
                    continue

                game = self.games_collection[game_id]
                if not game.space_id:
                    games_playtime[game_id] = GameTime(game_id, None, None)
                    continue

                try:
                    response = await self.client.get_game_stats(game.space_id)
                except ApplicationError as err:
                    self._game_time_import_failure(game_id, err)
                    continue

                statscards = response.get('Statscards', None)
                if statscards is None:
                    blacklist[game_id] = current_time + 3600 * 24 * 14  # two weeks
                    games_playtime[game_id] = GameTime(game_id, None, None)
                    continue

                playtime, last_played = find_times(statscards, game_id)
                if playtime == 0:
                    playtime = None
                if last_played == 0:
                    last_played = None
                log.info(f'Stats for {game.name}: playtime: {playtime}, last_played: {last_played}')
                games_playtime[game_id] = GameTime(game_id, playtime, last_played)

            except Exception as e:
                log.error(f"Getting game times for game {game_id} has crashed: " + repr(e))
                self._game_time_import_failure(game_id, UnknownError())

        self.persistent_cache['games_without_stats'] = json.dumps(blacklist)
        self.push_cache()
        return games_playtime

    if SYSTEM == System.WINDOWS:
        async def launch_game(self, game_id):
            if not self.parsed_local_games:
                await self.get_local_games()
            elif not self.user_can_perform_actions():
                return

            for game in self.games_collection.get_local_games():
                if (game.space_id == game_id or game.install_id == game_id or game.launch_id == game_id) and game.status == GameStatus.Installed:
                    if game.type == GameType.Steam:
                        if is_steam_installed():
                            url = f"start steam://rungameid/{game.third_party_id}"
                        else:
                            url = f"start uplay://open/game/{game.launch_id}"
                    elif game.type == GameType.New or game.type == GameType.Legacy:
                        log.debug('Launching game')
                        self.game_status_notifier._legacy_game_launched = True
                        url = f"start uplay://launch/{game.launch_id}"
                    else:
                        log.error(f"Unsupported game type {game.name}")
                        self.open_uplay_client()
                        return

                    log.info(f"Launching game '{game.name}' by protocol: [{url}]")

                    subprocess.Popen(url, shell=True)
                    self.reset_tick_count()
                    return

            for game in self.games_collection:
                if (game.space_id == game_id or game.install_id == game_id) and game.status in [GameStatus.NotInstalled,
                                                                                                GameStatus.Unknown]:
                    log.warning("Game is not installed, installing")
                    return await self.install_game(game_id)

            log.info("Failed to launch game, launching client instead.")
            self.open_uplay_client()

    if SYSTEM == System.WINDOWS:
        async def install_game(self, game_id, retry=False):
            log.debug(self.games_collection)
            if not self.user_can_perform_actions():
                return

            for game in self.games_collection:
                game_ids = [game.space_id, game.install_id, game.launch_id]
                if (game_id in game_ids) and game.owned and game.status in [GameStatus.NotInstalled,
                                                                            GameStatus.Unknown]:
                    if game.install_id:
                        log.info(f"Installing game: {game_id}, {game}")
                        subprocess.Popen(f"start uplay://install/{game.install_id}", shell=True)
                        return
                if (game_id in game_ids) and game.status == GameStatus.Installed:
                    log.warning("Game already installed, launching")
                    return await self.launch_game(game_id)

            # if launch_id is not known, try to launch local client instead
            self.open_uplay_client()
            log.info(
                f"Did not found game with game_id: {game_id}, proper launch_id and NotInstalled status, launching client.")

    if SYSTEM == System.WINDOWS:
        async def uninstall_game(self, game_id):
            if not self.user_can_perform_actions():
                return

            for game in self.games_collection.get_local_games():
                if (game.space_id == game_id or game.launch_id == game_id) and game.status == GameStatus.Installed:
                    subprocess.Popen(f"start uplay://uninstall/{game.launch_id}", shell=True)
                    return

            self.open_uplay_client()
            log.info(
                f"Did not found game with game_id: {game_id}, proper launch_id and Installed status, launching client.")

    def user_can_perform_actions(self):
        if not self.local_client.is_installed:
            self.open_uplay_browser()
            return False
        if not self.local_client.was_user_logged_in:
            self.open_uplay_client()
            return False
        return True

    def open_uplay_client(self):
        subprocess.Popen("start uplay://", shell=True)

    def open_uplay_browser(self):
        url = 'https://www.ubisoft.com/en-us/ubisoft-connect'
        log.info(f"Opening uplay website: {url}")
        webbrowser.open(url, autoraise=True)

    def refresh_game_statuses(self):
        if not self.local_client.was_user_logged_in:
            return
        statuses = self.game_status_notifier.statuses
        new_games = []
        for game in self.games_collection:
            try:
                if statuses[game.install_id] == GameStatus.Installed and game.status in [GameStatus.NotInstalled,
                                                                                         GameStatus.Unknown]:
                    log.info(f"updating status for {game.name} to installed from not installed")
                    game.status = GameStatus.Installed
                    self.update_local_game_status(game.as_local_game())
                elif statuses[game.install_id] == GameStatus.Installed and game.status == GameStatus.Running:
                    log.info(f"updating status for {game.name} to installed from running")
                    game.status = GameStatus.Installed
                    self.update_local_game_status(game.as_local_game())
                    asyncio.create_task(self.prevent_uplay_from_showing())
                elif statuses[game.install_id] == GameStatus.Running and game.status != GameStatus.Running:
                    log.info(f"updating status for {game.name} to running")
                    game.status = GameStatus.Running
                    self.update_local_game_status(game.as_local_game())
                elif statuses[game.install_id] in [GameStatus.NotInstalled, GameStatus.Unknown] and game.status not in [GameStatus.NotInstalled, GameStatus.Unknown]:
                    log.info(f"updating status for {game.name} to not installed")
                    game.status = GameStatus.NotInstalled
                    self.update_local_game_status(game.as_local_game())
            except KeyError:
                continue

            if self.owned_games_sent and not game.considered_for_sending:
                game.considered_for_sending = True
                new_games.append(game)

        if new_games:
            asyncio.create_task(self._add_new_games(new_games))

    async def get_friends(self):
        friends = await self.client.get_friends()
        return [
            FriendInfo(user_id=friend["pid"], user_name=friend["nameOnPlatform"])
            for friend in friends["friends"]
        ]

    async def get_subscriptions(self) -> List[Subscription]:
        sub_status = await self.client.get_subscription()
        sub_status = True if sub_status else False
        return [Subscription(subscription_name="Ubisoft+", end_time=None, owned=sub_status,
                             subscription_discovery=SubscriptionDiscovery.AUTOMATIC)]

    async def prepare_subscription_games_context(self, subscription_names: List[str]) -> Any:
        data = await self.client.get_subscription_games()
        if data:
            return [SubscriptionGame(game_title=(g.get('name') or 'Unknown'), game_id=str(g.get('ubisoftConnectGameId') or g.get('uplayGameId'))) for g in data if (g.get('ubisoftConnectGameId') or g.get('uplayGameId'))]
        return None

    async def get_subscription_games(self, subscription_name: str, context: Any) -> AsyncGenerator[List[SubscriptionGame], None]:
        yield context

    if SYSTEM == System.WINDOWS:
        async def prepare_local_size_context(self, game_ids: List[str]) -> Any:
            local_paths = dict()
            for game in self.games_collection:
                for requested_id in game_ids:
                    if game.launch_id == requested_id or game.space_id == requested_id:
                        local_paths[requested_id] = get_local_game_path(game.special_registry_path, game.launch_id)
            return local_paths

        async def get_local_size(self, game_id: str, context: Any) -> Optional[int]:
            if game_id in context:
                return await get_size_at_path(context[game_id])

    if SYSTEM == System.WINDOWS:
        async def launch_platform_client(self):
            if self.local_client.is_running():
                log.info("Launch platform client called but Uplay is already running")
                return
            url = "start uplay://"
            subprocess.Popen(url, shell=True)
            # Uplay tries to get focus a couple of times when being launched
            end_time = time.time() + 15
            while time.time() <= end_time:
                await self.prevent_uplay_from_showing(kill_attempt=False)
                await asyncio.sleep(0.05)

    if SYSTEM == System.WINDOWS:
        async def shutdown_platform_client(self):
            if self.local_client.is_installed:
                subprocess.Popen("taskkill.exe /im \"upc.exe\"", shell=True)

    if SYSTEM == System.WINDOWS:
        async def prevent_uplay_from_showing(self, kill_attempt=True):
            if not self.local_client.is_installed:
                log.info("Local client not installed")
                return
            client_popup_wait_time = 5
            check_frequency_delay = 0.02

            end_time = time.time() + client_popup_wait_time
            hwnd = ctypes.windll.user32.FindWindowW(None, "Ubisoft Connect")
            while not ctypes.windll.user32.IsWindowVisible(hwnd):
                if time.time() >= end_time:
                    log.info("Timed out post close game uplay popup")
                    break
                hwnd = ctypes.windll.user32.FindWindowW(None, "Ubisoft Connect")
                await asyncio.sleep(check_frequency_delay)
            if kill_attempt:
                await self.shutdown_platform_client()
            else:
                ctypes.windll.user32.SetForegroundWindow(hwnd)
                ctypes.windll.user32.CloseWindow(hwnd)

    if SYSTEM == System.WINDOWS:
        async def prepare_game_library_settings_context(self, game_ids):
            if self.local_client.settings_accessible():
                library_context = {}
                settings_data = self.local_client.read_settings()
                parser = LocalParser()
                favorite_games, hidden_games = parser.get_game_tags(settings_data)
                for game_id in game_ids:
                    try:
                        game = self.games_collection[game_id]
                    except KeyError:
                        continue
                    library_context[game_id] = {'favorite': game.launch_id in favorite_games,
                                                'hidden': game.launch_id in hidden_games}
                return library_context
            return None

        async def get_game_library_settings(self, game_id, context):
            log.debug(f"Context {context}")
            if not context:
                # Unable to retrieve context
                return GameLibrarySettings(game_id, None, None)
            game_library_settings = context.get(game_id)
            if game_library_settings is None:
                # Able to retrieve context but game is not in its values -> It doesnt have any tags or hidden status set
                return GameLibrarySettings(game_id, [], False)
            return GameLibrarySettings(game_id, ['favorite'] if game_library_settings['favorite'] else [],
                                       game_library_settings['hidden'])

    def reset_tick_count(self):
        # Resetting tick count ensures that certain operations performed on tick will be made with a known delay.
        self.tick_count = 0

    def tick(self):
        loop = asyncio.get_event_loop()
        if SYSTEM == System.WINDOWS:
            self.tick_count += 1
            if self.tick_count % 1 == 0:
                self.refresh_game_statuses()
            if self.tick_count % 5 == 0:
                if self.local_client.launcher_log_path is None:
                    self.game_status_notifier.launcher_log_path = None
            if self.tick_count % 9 == 0:
                self._update_local_games_status()
                if self.local_client.ownership_changed():
                    if not self.updating_games:
                        log.info('Ownership file has been changed or created. Reparsing.')
                        loop.run_in_executor(None, self._update_games)
        return

    async def shutdown(self):
        log.info("Plugin shutdown.")
        await self.client.close()


def main():
    multiprocessing.freeze_support()
    create_and_run_plugin(UplayPlugin, sys.argv)


if __name__ == "__main__":
    main()
