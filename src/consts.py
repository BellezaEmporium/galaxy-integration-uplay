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

OVERLAY_SPACE_ID = "0a706b37-4b88-4437-b8f4-4ed2458c9518" # from webpage
OVERLAY_APP_ID   = "20adeb9c-6dad-404e-af1e-b12b4594e86e" # from webpage

OVERLAY_LOGIN_URL = (
    f"https://connect.cdn.ubisoft.com/overlay/default/"
    f"?env=prod&isStandalone=true&platform=pc&deviceType=desktop"
    f"&locale=en-US&spaceId={OVERLAY_SPACE_ID}&applicationId={OVERLAY_APP_ID}"
    f"&country=US&region=WW&ownershipGroup=empty"
)


AUTH_JS = {
    regex_pattern(r"connect.cdn.ubisoft.com/overlay"): [
        r'''
        (function() {
            var _capturedSession = null;

            function tryRedirect(data) {
                if (data && data.ticket && !data.twoFactorAuthenticationTicket) {
                    _capturedSession = data;
                }
            }

            function doRedirect() {
                if (_capturedSession) {
                    var payload = encodeURIComponent(JSON.stringify(_capturedSession));
                    window.location.replace("https://galaxy.auth.local/ubisoft#" + payload);
                }
            }

            var _open = XMLHttpRequest.prototype.open;
            var _send = XMLHttpRequest.prototype.send;

            XMLHttpRequest.prototype.open = function(method, url) {
                this._xurl = url; this._xmethod = method;
                return _open.apply(this, arguments);
            };

            XMLHttpRequest.prototype.send = function(body) {
                var xhr = this;
                var orig = xhr.onreadystatechange;
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 200 && xhr._xurl) {
                        if (xhr._xurl.indexOf("/v3/profiles/sessions") !== -1
                                && xhr._xmethod && xhr._xmethod.toUpperCase() === "POST") {
                            try { tryRedirect(JSON.parse(xhr.responseText)); } catch(e) {}
                        }
                        if (xhr._xurl.indexOf("/v4/spaces/global/ubiconnect/configcache/api/postauth") !== -1) {
                            doRedirect();
                        }
                    }
                    if (orig) orig.apply(this, arguments);
                };
                return _send.apply(this, arguments);
            };

            var _fetch = window.fetch;
            window.fetch = function(input, init) {
                var url = (typeof input === "string") ? input : (input && input.url) || "";
                var method = (init && init.method) ? init.method.toUpperCase() : "GET";
                return _fetch.apply(this, arguments).then(function(response) {
                    if (response.ok) {
                        if (url.indexOf("/v3/profiles/sessions") !== -1 && method === "POST") {
                            response.clone().json().then(tryRedirect).catch(function(){});
                        }
                        if (url.indexOf("/v4/spaces/global/ubiconnect/configcache/api/postauth") !== -1) {
                            doRedirect();
                        }
                    }
                    return response;
                });
            };
        })();
        '''
    ],
    # 2FA - email
    regex_pattern(r"connect\.ubisoft\.com/two-fa-email"): [
        r'''
        let rdCheckbox = document.getElementById("rdCheckbox");
        if (rdCheckbox) { rdCheckbox.checked = true; }
        let deviceNameField = document.querySelector("input[name='deviceName']");
        if (deviceNameField) { deviceNameField.value = "GOG Galaxy"; }
        '''
    ],
}