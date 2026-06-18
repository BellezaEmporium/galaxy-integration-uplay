import logging as log
import re
import time
from threading import Lock, Thread

import psutil
from file_read_backwards import FileReadBackwards

from definitions import UbisoftGame, GameType, GameStatus, ProcessType, WatchedProcess, SYSTEM, System
from local_helper import get_local_game_path, get_game_installed_status
from steam import get_steam_game_status


_GAME_STARTED_RE = re.compile(r"Game with process id (\d+) has been started")


class ProcessWatcher:
    def __init__(self) -> None:
        self._lock = Lock()
        self.watched_processes: list[WatchedProcess] = []

    def watch_process(self, process, game: UbisoftGame | None = None) -> WatchedProcess | None:
        try:
            watched = WatchedProcess(
                process=process,
                timeout=time.time() + 30,
                type=ProcessType.Game if game else ProcessType.Launcher,
                game=game,
            )
            with self._lock:
                self.watched_processes.append(watched)
            return watched
        except (psutil.Error, OSError, TypeError, ValueError):
            return None

    def update_watched_processes_list(self) -> None:
        try:
            with self._lock:
                alive_processes: list[WatchedProcess] = []
                for proc in self.watched_processes:
                    if proc.process.is_running():
                        alive_processes.append(proc)
                    else:
                        log.info("Removing %s", proc)
                self.watched_processes = alive_processes
        except Exception as e:
            log.error("Error removing process from watched processes list %r", e)

    def get_watched_processes(self) -> list[WatchedProcess]:
        with self._lock:
            return list(self.watched_processes)


class GameStatusNotifier:
    def __init__(self, process_watcher: ProcessWatcher) -> None:
        self.process_watcher = process_watcher
        self.games: dict[str, UbisoftGame] = {}
        self.statuses: dict[str, GameStatus] = {}
        self.launcher_log_path: str | None = None
        self._legacy_game_launched = False
        self._lock = Lock()

        if SYSTEM == System.WINDOWS:
            Thread(target=self._process_data, daemon=True).start()

    def update_game(self, game: UbisoftGame) -> None:
        with self._lock:
            existing = self.games.get(game.install_id)
            if existing and game.path == existing.path:
                return
            self.games[game.install_id] = game

    def _is_process_alive(self, game: UbisoftGame) -> bool:
        try:
            self.process_watcher.update_watched_processes_list()
            for process in self.process_watcher.get_watched_processes():
                if process.type == ProcessType.Game and process.game and process.game.install_id == game.install_id:
                    return True
            return False
        except Exception as e:
            log.error("Error checking if process is alive %r", e)
            return False

    def _get_process_by_path(self, game: UbisoftGame) -> int | None:
        if not game.path:
            return None

        game_path = game.path.lower()
        for proc in psutil.process_iter(attrs=["exe"], ad_value=""):
            exe_path = (proc.info.get("exe") or "").lower()
            if not exe_path or game_path not in exe_path:
                continue

            try:
                parent = proc.parent()
                if parent is not None and parent.exe() == game.path:
                    return parent.pid
                return proc.pid
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue

        return None

    def _handle_legacy_game_log(self, game: UbisoftGame) -> bool:
        if self._legacy_game_launched:
            pid = self._get_process_by_path(game)
            if pid:
                watched = self.process_watcher.watch_process(psutil.Process(pid), game)
                if watched:
                    self._legacy_game_launched = False
                    return True
            return False

        return self._is_process_alive(game)

    def _read_log_data(self, game: UbisoftGame, log_line: str) -> bool | None:
        if "disconnected" in log_line:
            return False

        if "has been started with product id" in log_line and f" {game.launch_id} (" in log_line:
            match = _GAME_STARTED_RE.search(log_line)
            if match:
                try:
                    pid = int(match.group(1))
                    watched = self.process_watcher.watch_process(psutil.Process(pid), game)
                    return watched is not None
                except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
                    return False

        if game.type == GameType.Legacy and "Failed to fetch ubiplus game. Missing space id" in log_line:
            return self._handle_legacy_game_log(game)

        return None

    def _parse_log(self, game: UbisoftGame, line_list: list[str]) -> bool:
        if not line_list:
            return False

        try:
            for log_line in reversed(line_list):
                game_status = self._read_log_data(game, log_line)
                if game_status is not None:
                    return game_status
            return False
        except Exception as e:
            log.error("Error parsing launcher log file is game running %r", e)
            return False

    def _is_game_running(self, game: UbisoftGame, line_list: list[str]) -> bool:
        try:
            current_status = self.statuses.get(game.install_id)
            if current_status == GameStatus.Running:
                return self._is_process_alive(game)
            return self._parse_log(game, line_list)
        except Exception as e:
            log.error("Error in checking is game running %s / %r", game.launch_id, e)
            return False

    def _get_launcher_log_lines(self, number_of_lines: int) -> list[str]:
        line_list: list[str] = []

        if self.launcher_log_path:
            try:
                with FileReadBackwards(self.launcher_log_path, encoding="utf-8") as fh:
                    for _ in range(number_of_lines):
                        line = fh.readline()
                        if not line:
                            break
                        line_list.append(line)
            except FileNotFoundError:
                pass
            except UnicodeDecodeError:
                log.warning(
                    "Can't read launcher log at %s, UnicodeDecodeError when reading log lines",
                    self.launcher_log_path,
                )
            except Exception as e:
                log.warning(
                    "Can't read launcher log at %s, unable to read running games statuses: %r",
                    self.launcher_log_path,
                    e,
                )

        return line_list[::-1]

    def _get_game_status(self, game: UbisoftGame, line_list: list[str]) -> GameStatus:
        if game.type == GameType.Steam:
            return get_steam_game_status(game.path)

        game_path = game.path or get_local_game_path(game.special_registry_path, game.launch_id)

        status = get_game_installed_status(game_path, game.exe, game.special_registry_path)
        if status == GameStatus.Installed and self._is_game_running(game, line_list):
            return GameStatus.Running
        return status

    def _process_data(self) -> None:
        while True:
            line_list = self._get_launcher_log_lines(20)

            try:
                with self._lock:
                    games_snapshot = list(self.games.items())

                new_statuses: dict[str, GameStatus] = {}
                for install_id, game in games_snapshot:
                    new_statuses[install_id] = self._get_game_status(game, line_list)

                with self._lock:
                    self.statuses.update(new_statuses)

            except Exception as e:
                log.error("Process data error %r", e)

            time.sleep(1)