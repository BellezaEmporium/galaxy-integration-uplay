import os
from definitions import System, SYSTEM
import re
from functools import lru_cache
from pathlib import Path

_local_appdata = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")

UBISOFT_REGISTRY = "SOFTWARE\\Ubisoft"
STEAM_REGISTRY = "Software\\Valve\\Steam"
UBISOFT_REGISTRY_LAUNCHER = "SOFTWARE\\Ubisoft\\Launcher"
UBISOFT_WOW6432_REGISTRY_LAUNCHER = "SOFTWARE\\WOW6432Node\\Ubisoft\\Launcher"
UBISOFT_REGISTRY_LAUNCHER_INSTALLS = "SOFTWARE\\Ubisoft\\Launcher\\Installs"
APPDATA_PATH = _local_appdata / "Ubisoft Game Launcher"

if SYSTEM == System.WINDOWS:
    UBISOFT_SETTINGS_YAML = str(APPDATA_PATH / "settings.yaml")

UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES: frozenset[str] = frozenset(
    ["gamename", "l1", "", "ubisoft game", "name"]
)
UBISOFT_LOGIN_APPID = "1068ef52-dfd2-4e62-8ac9-37a47e6c0b78" # This one doesn't seem to need any Genome ID, new login flow (account info v2)
UBISOFT_APPID = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6" # Hardcoded Ubisoft AppID from EXE
UBISOFT_GENOMEID = "954e66a0-be1b-4aa0-9690-fb75201e4e9e" # Hardcoded Ubisoft GenomeID from EXE
CHROME_USERAGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) ConnectPC Safari/537.36"

@lru_cache(maxsize=None)
def regex_pattern(regex: str) -> str:
    return ".*" + re.escape(regex) + ".*"


AUTH_JS = { regex_pattern(r"connect.ubisoft.com/ready"): [
            r'''
            window.location.replace("https://connect.ubisoft.com/change_domain/"); 
            '''
        ],
            regex_pattern(r"connect.ubisoft.com/change_domain"): [
            r'''
            window.location.replace(localStorage.getItem("PRODloginData") +","+ localStorage.getItem("PRODrememberMe") +"," + localStorage.getItem("PRODlastProfile"));
            '''
        ],
            # Very specific, as email = email 2FA.
            regex_pattern(r"connect.ubisoft.com/two-fa-email"): [
            r'''
                // Auto-check remember device checkbox
                let rdCheckbox = document.getElementById("rdCheckbox");
                if (rdCheckbox) {
                    rdCheckbox.checked = true;
                }
                
                // Set device name to "GOG Galaxy"
                let deviceNameField = document.querySelector("input[id='DeviceName']");
                if (deviceNameField) {
                    deviceNameField.value = "GOG Galaxy";
                }
            '''
        ],
            # Very specific, as ga = Google Authenticator. Same points, different page.
            regex_pattern(r"connect.ubisoft.com/two-fa-ga"): [
            r'''
                // Auto-check remember device checkbox
                let rdCheckbox = document.getElementById("rdCheckbox");
                if (rdCheckbox) {
                    rdCheckbox.checked = true;
                }
                
                // Set device name to "GOG Galaxy"
                let deviceNameField = document.querySelector("input[id='DeviceName']");
                if (deviceNameField) {
                    deviceNameField.value = "GOG Galaxy";
                }
            '''
        ]
}

