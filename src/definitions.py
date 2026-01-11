import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import psutil as psutil

from galaxy.api.types import LocalGameState, LocalGame, Game, LicenseInfo, LicenseType


class System(Enum):
    WINDOWS = 1
    MACOS = 2
    LINUX = 3


if sys.platform == 'win32':
    SYSTEM = System.WINDOWS
elif sys.platform == 'darwin':
    SYSTEM = System.MACOS


class GameType(Enum):
    New = "New"
    Legacy = "Legacy"
    Steam = "Steam"
    Origin = "Origin"


class GameStatus(Enum):
    Unknown = "Unknown"
    NotInstalled = "NotInstalled"
    Installed = "Installed"
    Running = "Running"


GameStatusTranslator = {
    GameStatus.Unknown: LocalGameState.None_,
    GameStatus.NotInstalled: LocalGameState.None_,
    GameStatus.Installed: LocalGameState.Installed,
    GameStatus.Running: LocalGameState.Installed | LocalGameState.Running
}


class ProcessType(Enum):
    Launcher = "Launcher"
    Game = "Game"


@dataclass
class UbisoftGame(object):
    space_id: str
    launch_id: str
    install_id: str
    third_party_id: str
    name: str
    path: str
    type: GameType
    special_registry_path: str
    exe: str
    owned: Optional[bool] = None
    considered_for_sending: bool = False
    status: Optional[GameStatus] = GameStatus.Unknown
    activation_id: str = ''

    def as_local_game(self):
        status = self.status if self.status is not None else GameStatus.Unknown
        if not self.space_id:
            return LocalGame(self.launch_id, GameStatusTranslator[status])
        else:
            return LocalGame(self.space_id, GameStatusTranslator[status])

    def as_galaxy_game(self):
        passed_id = self.space_id if self.space_id else self.launch_id
        return Game(passed_id, self.name, [], LicenseInfo(LicenseType.SinglePurchase))

@dataclass
class WatchedProcess(object):
    process: psutil.Process
    timeout: float
    type: ProcessType
    game: Optional[UbisoftGame]
