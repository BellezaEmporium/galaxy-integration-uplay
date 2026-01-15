import os
from definitions import System, SYSTEM
import re
UBISOFT_REGISTRY = "SOFTWARE\\Ubisoft"
STEAM_REGISTRY = "Software\\Valve\\Steam"
UBISOFT_REGISTRY_LAUNCHER = "SOFTWARE\\Ubisoft\\Launcher"
UBISOFT_REGISTRY_LAUNCHER_INSTALLS = "SOFTWARE\\Ubisoft\\Launcher\\Installs"
LOCAL_APPDATA = os.getenv("LOCALAPPDATA")
APPDATA_PATH = os.path.join(LOCAL_APPDATA, "Ubisoft Game Launcher")

if SYSTEM == System.WINDOWS:
    UBISOFT_SETTINGS_YAML = os.path.join(os.getenv('LOCALAPPDATA', ''), 'Ubisoft Game Launcher', 'settings.yaml')

UBISOFT_CONFIGURATIONS_BLACKLISTED_NAMES = ["gamename", "l1", '', 'ubisoft game', 'name']
UBISOFT_APPID = "f68a4bb5-608a-4ff2-8123-be8ef797e0a6" # Hardcoded Ubisoft AppID from EXE
UBISOFT_GENOMEID = "954e66a0-be1b-4aa0-9690-fb75201e4e9e" # Hardcoded Ubisoft GenomeID from EXE
CHROME_USERAGENT = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) ConnectPC Safari/537.36"
UBI_USERAGENT = "Massgate_169.4.0.12978"

def regex_pattern(regex):
    return ".*" + re.escape(regex) + ".*"


AUTH_JS = {regex_pattern(r"connect.ubisoft.com/ready"): [
            r'''
            window.location.replace("https://connect.ubisoft.com/change_domain/"); 
            '''
        ],
            regex_pattern(r"connect.ubisoft.com/change_domain"): [
            r'''
            window.location.replace(localStorage.getItem("PRODloginData") +","+ localStorage.getItem("PRODrememberMe") +"," + localStorage.getItem("PRODlastProfile"));
            '''
        ],
            regex_pattern(r"connect.ubisoft.com/two-fa-email"): [
            r'''
            // Auto-check remember device checkbox
            let rdCheckbox = document.getElementById("rdCheckbox");
            if (rdCheckbox) {
                rdCheckbox.checked = true;
            }
            
            // Set device name to "GOG Galaxy"
            let deviceNameField = document.querySelector("input[name='deviceName']");
            if (deviceNameField) {
                deviceNameField.value = "GOG Galaxy";
            }
            '''
        ]}

