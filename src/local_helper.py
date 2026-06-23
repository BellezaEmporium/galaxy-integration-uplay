from definitions import SYSTEM, System, GameStatus

import os
import asyncio
import logging as log
from consts import UBISOFT_REGISTRY_LAUNCHER_INSTALLS

if SYSTEM == System.WINDOWS:
    import winreg

_REG_FLAGS = winreg.KEY_READ | winreg.KEY_WOW64_32KEY

def _get_registry_value_from_path(top_key, registry_path, key):
    with winreg.OpenKey(top_key, registry_path, 0, _REG_FLAGS) as winkey:
        return winreg.QueryValueEx(winkey, key)[0]


def _return_local_game_path_from_special_registry(special_registry_path):
    if not special_registry_path:
        return GameStatus.NotInstalled
    try:
        return _get_registry_value_from_path(
            winreg.HKEY_LOCAL_MACHINE, special_registry_path, "InstallLocation"
        )
    except WindowsError:
        return ""
    except Exception as e:
        log.warning(f"Unable to read special registry status for {special_registry_path}: {repr(e)}")
        return ""


def _return_local_game_path(launch_id):
    installs_path = UBISOFT_REGISTRY_LAUNCHER_INSTALLS
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, installs_path, 0, _REG_FLAGS):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{installs_path}\\{launch_id}", 0, _REG_FLAGS) as lkey:
                    game_path, _ = winreg.QueryValueEx(lkey, "InstallDir")
                    return os.path.normcase(os.path.normpath(game_path))
            except OSError:
                return ""
    except WindowsError:
        return ""


def get_local_game_path(special_registry_path, launch_id):
    local_game_path = _return_local_game_path(launch_id)
    if not local_game_path and special_registry_path:
        local_game_path = _return_local_game_path_from_special_registry(special_registry_path)
    return local_game_path


async def get_size_at_path(start_path):
    total_size = 0
    for dirpath, _, filenames in os.walk(start_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
                await asyncio.sleep(0)
    return total_size


def _is_file_at_path(path, file):
    return os.path.isfile(os.path.join(path, file)) if os.path.isdir(path) else False


def _read_status_from_state_file(game_path):
    state_file = os.path.join(game_path, "uplay_install.state")
    try:
        if os.path.exists(state_file):
            with open(state_file, "rb") as f:
                return GameStatus.Installed if f.read(1)[0] == 0x0A else GameStatus.NotInstalled
        return GameStatus.NotInstalled
    except Exception as e:
        log.warning(f"Issue reading install state file for {game_path}: {repr(e)}")
        return GameStatus.NotInstalled


def get_game_installed_status(path, exe=None, special_registry_path=None):
    status = GameStatus.NotInstalled
    try:
        if path and os.access(path, os.F_OK):
            status = _read_status_from_state_file(path)
            if status == GameStatus.NotInstalled and exe and special_registry_path:
                if _is_file_at_path(path, exe):
                    status = GameStatus.Installed
    except Exception as e:
        log.error(f"Error reading game installed status at {path}: {repr(e)}")
    return status