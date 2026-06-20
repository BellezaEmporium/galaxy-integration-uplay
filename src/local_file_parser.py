import logging as log
import math
from typing import Any

import yaml

from local_helper import get_local_game_path, get_game_installed_status
from steam import get_steam_game_status
from consts import UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES
from definitions import UbisoftGame, GameType, GameStatus

_MIN_YAML_SIZE = 64

class LocalParser:
    def __init__(self) -> None:
        self.configuration_raw: bytes | bytearray | None = None
        self.ownership_raw: bytes | bytearray | None = None
        self.settings_raw: bytes | bytearray | None = None

    @staticmethod
    def _convert_data(data: int) -> int:
        if data > 256 * 256:
            data = data - (128 * 256 * math.ceil(data / (256 * 256)))
            data = data - (128 * math.ceil(data / 256))
        elif data > 256:
            data = data - (128 * math.ceil(data / 256))
        return data

    def _decode_game_id(self, data: bytes | bytearray | list[int], rec_size: int) -> str:
        i = 0
        multiplier = 1
        game_id = 0

        while i < rec_size:
            game_id += data[i] * multiplier
            multiplier *= 256
            i += 1

        return str(self._convert_data(game_id))

    def _parse_configuration_header(
        self, header: bytes | bytearray, second_eight: bool = False
    ) -> tuple[int, int, int, int]:
        try:
            offset = 1
            multiplier = 1
            record_size = 0
            tmp_size = 0

            if second_eight:
                while header[offset] != 0x08 or (
                    header[offset] == 0x08 and header[offset + 1] == 0x08
                ):
                    record_size += header[offset] * multiplier
                    multiplier *= 256
                    offset += 1
                    tmp_size += 1
            else:
                while header[offset] != 0x08 or record_size == 0:
                    record_size += header[offset] * multiplier
                    multiplier *= 256
                    offset += 1
                    tmp_size += 1

            record_size = self._convert_data(record_size)

            offset += 1

            multiplier = 1
            launch_id = 0
            while header[offset] != 0x10 or header[offset + 1] == 0x10:
                launch_id += header[offset] * multiplier
                multiplier *= 256
                offset += 1

            launch_id = self._convert_data(launch_id)

            offset += 1

            multiplier = 1
            launch_id_2 = 0
            while header[offset] != 0x1A or (
                header[offset] == 0x1A and header[offset + 1] == 0x1A
            ):
                launch_id_2 += header[offset] * multiplier
                multiplier *= 256
                offset += 1

            launch_id_2 = self._convert_data(launch_id_2)

            if record_size - offset < 128 <= record_size:
                tmp_size -= 1
                record_size += 1

            return record_size - offset, launch_id, launch_id_2, offset + tmp_size + 1

        except (IndexError, TypeError, ValueError):
            return 0, 0, 0, 10

    def _parse_ownership_header(
        self, header: bytes | bytearray
    ) -> tuple[int | None, int | None, int | None]:
        try:
            offset = 1
            multiplier = 1
            record_size = 0
            tmp_size = 0

            if header[offset - 1] != 0x0A:
                return None, None, None

            while header[offset] != 0x08 or record_size == 0:
                record_size += header[offset] * multiplier
                multiplier *= 256
                offset += 1
                tmp_size += 1

            record_size = self._convert_data(record_size)

            offset += 1

            multiplier = 1
            launch_id = 0
            while header[offset] != 0x10 or header[offset + 1] == 0x10:
                launch_id += header[offset] * multiplier
                multiplier *= 256
                offset += 1

            launch_id = self._convert_data(launch_id)

            offset += 1

            multiplier = 1
            launch_id_2 = 0
            while header[offset] != 0x22:
                launch_id_2 += header[offset] * multiplier
                multiplier *= 256
                offset += 1

            launch_id_2 = self._convert_data(launch_id_2)
            return launch_id, launch_id_2, record_size + tmp_size + 1

        except (IndexError, TypeError, ValueError):
            return None, None, None

    def _parse_configuration(self) -> dict[int, dict[str, int]]:
        configuration_content = self.configuration_raw
        global_offset = 0
        records: dict[int, dict[str, int]] = {}

        if configuration_content:
            try:
                while global_offset < len(configuration_content):
                    data = configuration_content[global_offset:]
                    object_size, install_id, launch_id, header_size = self._parse_configuration_header(data)

                    launch_id = install_id if launch_id == 0 or launch_id == install_id else launch_id

                    if object_size > _MIN_YAML_SIZE:
                        records[install_id] = {
                            "size": object_size,
                            "offset": global_offset + header_size,
                            "install_id": install_id,
                            "launch_id": launch_id,
                        }

                    global_offset_tmp = global_offset
                    global_offset += object_size + header_size

                    if (
                        global_offset < len(configuration_content)
                        and configuration_content[global_offset] != 0x0A
                    ):
                        object_size, _, _, header_size = self._parse_configuration_header(data, True)
                        global_offset = global_offset_tmp + object_size + header_size

            except (IndexError, TypeError, ValueError):
                log.exception(
                    "parse_configuration failed with exception. Possibly 'configuration' file corrupted"
                )

        return records

    def _parse_ownership(self) -> list[int]:
        ownership_content = self.ownership_raw
        global_offset = 0x108
        records: list[int] = []

        if ownership_content is None:
            return []

        try:
            while global_offset < len(ownership_content):
                data = ownership_content[global_offset:]
                launch_id, launch_id_2, record_size = self._parse_ownership_header(data)

                if not launch_id:
                    break

                records.append(launch_id)
                if launch_id_2 != launch_id:
                    records.append(launch_id_2)

                if record_size is None:
                    break

                global_offset += record_size

        except (IndexError, TypeError, ValueError):
            log.exception("parse_ownership failed with exception. Possibly 'ownership' file corrupted")
            return []

        return records

    def _parse_user_settings(self) -> tuple[set[str], set[str]]:
        global_offset = 1
        fav: set[str] = set()
        hidden: set[str] = set()
        data = self.settings_raw

        if data is not None and len(data) > global_offset and data[global_offset] != 0:
            buffer = int(data[global_offset])
            fav_records = data[global_offset + 1:global_offset + buffer + 1]
        else:
            fav_records = []

        global_offset = len(fav_records) + 3
        if data is not None and len(data) > global_offset and data[global_offset] != 0:
            buffer = int(data[global_offset])
            hidden_records = data[global_offset + 1:global_offset + buffer + 1]
        else:
            hidden_records = []

        pos = 0
        while pos + 3 <= len(fav_records):
            rec_size = fav_records[pos + 1] - 1
            if rec_size < 0 or pos + 3 + rec_size > len(fav_records):
                break
            rec_data = fav_records[pos + 3:pos + 3 + rec_size]
            fav.add(self._decode_game_id(rec_data, rec_size))
            pos += rec_size + 3

        pos = 0
        while pos + 3 <= len(hidden_records):
            rec_size = hidden_records[pos + 1] - 1
            if rec_size < 0 or pos + 3 + rec_size > len(hidden_records):
                break
            rec_data = hidden_records[pos + 3:pos + 3 + rec_size]
            hidden.add(self._decode_game_id(rec_data, rec_size))
            pos += rec_size + 3

        return fav, hidden

    def _get_game_name_from_yaml(self, game_yaml: dict[str, Any]) -> str:
        root = game_yaml.get("root", {})
        game_name = root.get("name", "")

        default_localizations = game_yaml.get("localizations", {}).get("default", {})

        if game_name.lower() in UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES:
            game_name = default_localizations.get("l1", game_name)

        if game_name.lower() in UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES:
            game_name = default_localizations.get("GAMENAME", game_name)

        if game_name.lower() in UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES:
            game_name = root.get("installer", {}).get("game_identifier", game_name)

        return game_name

    def _get_steam_game_properties_from_yaml(self, game_yaml: dict[str, Any]) -> tuple[str, str]:
        start_game = game_yaml.get("root", {}).get("start_game", {})
        steam_data = start_game.get("third_party_steam") or start_game.get("steam") or {}
        path = steam_data.get("game_installation_status_register", "")
        third_party_id = steam_data.get("steam_app_id", "")
        return path, third_party_id

    def _get_registry_properties_from_yaml(self, game_yaml: dict[str, Any]) -> tuple[str, str]:
        start_game = game_yaml.get("root", {}).get("start_game", {})
        executables = start_game.get("online", {}).get("executables", [])
        if not executables:
            return "", ""

        executable = executables[0]
        registry_path = executable.get("working_directory", {}).get("register", "")
        exe = executable.get("path", {}).get("relative", "")
        special_registry_path = ""

        if "Uninstall" in registry_path and "HKEY_LOCAL_MACHINE\\" in registry_path:
            registry_path = registry_path.split("HKEY_LOCAL_MACHINE\\", 1)[1]
            registry_path = registry_path.split("\\InstallLocation", 1)[0]
            special_registry_path = registry_path

        return special_registry_path, exe

    def _parse_game(self, game_yaml: dict[str, Any], install_id: int, launch_id: int) -> UbisoftGame:
        root = game_yaml.get("root", {})

        path = ""
        space_id = ""
        third_party_id = ""
        special_registry_path = ""
        status = GameStatus.NotInstalled
        game_type = GameType.New
        exe = ""
        launch_id_str = str(launch_id)
        install_id_str = str(install_id)

        if "space_id" in root:
            space_id = root["space_id"]
        elif "crash_reporting" in root and "space_id" in root["crash_reporting"]:
            space_id = root["crash_reporting"]["space_id"]
        else:
            game_type = GameType.Legacy

        third_party_platform = root.get("third_party_platform", {})
        platform_name = third_party_platform.get("name", "").lower()

        if platform_name == "steam":
            game_type = GameType.Steam
            path, third_party_id = self._get_steam_game_properties_from_yaml(game_yaml)
            status = get_steam_game_status(path)
        elif platform_name == "origin":
            log.info("Origin game found %s", game_yaml)
        else:
            special_registry_path, exe = self._get_registry_properties_from_yaml(game_yaml)
            if not special_registry_path:
                log.info("Unable to read registry path for game %s", launch_id_str)

            path = get_local_game_path(special_registry_path, launch_id_str)
            if path:
                status = get_game_installed_status(path, exe, special_registry_path)
            if not isinstance(path, str):
                path = str(path) if path is not None else ""

        game_name = self._get_game_name_from_yaml(game_yaml)

        log.info(
            "Parsed game from configuration %s, %s, %s, %s",
            space_id, install_id_str, game_name, launch_id_str
        )

        return UbisoftGame(
            space_id=space_id,
            launch_id=launch_id_str,
            install_id=install_id_str,
            third_party_id=third_party_id,
            name=game_name,
            path=path,
            type=game_type,
            special_registry_path=special_registry_path,
            exe=exe,
            status=status,
        )

    def parse_games(self, configuration_data: bytes | bytearray):
        self.configuration_raw = configuration_data

        configuration_records = self._parse_configuration()
        for game in configuration_records.values():
            if not game["size"]:
                continue

            stream = self.configuration_raw[
                game["offset"]: game["offset"] + game["size"]
            ].decode("utf-8", errors="ignore")

            if not stream or "start_game" not in stream:
                continue

            try:
                yaml_object = yaml.safe_load(stream.replace("\t", " "))
            except yaml.YAMLError:
                log.exception(
                    "Failed to parse YAML for install_id=%s launch_id=%s",
                    game["install_id"],
                    game["launch_id"],
                )
                continue

            if isinstance(yaml_object, dict) and "root" in yaml_object:
                yield self._parse_game(yaml_object, game["install_id"], game["launch_id"])

    def get_owned_local_games(self, ownership_data: bytes | bytearray) -> list[int]:
        self.ownership_raw = ownership_data
        return self._parse_ownership()

    def get_game_tags(self, settings_data: bytes | bytearray) -> tuple[set[str], set[str]]:
        self.settings_raw = settings_data
        return self._parse_user_settings()