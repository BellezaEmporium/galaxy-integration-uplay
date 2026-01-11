from datetime import datetime
import json
import logging as log
from galaxy.http import create_tcp_connector, create_client_session
import dateutil.parser

import aiohttp
import asyncio
import time
from functools import wraps

from galaxy.api.errors import AuthenticationRequired, AccessDenied, UnknownError

from consts import CHROME_USERAGENT, UBISOFT_APPID, UBISOFT_GENOMEID
from http_client import HttpClient

# Constants
REFRESH_BUFFER_SECONDS = 300
KEEPALIVE_INTERVAL = 300
KEEPALIVE_JITTER = 10
KEEPALIVE_CHECK_THRESHOLD = 600
CACHE_VALIDITY_SECONDS = 604800

UBI_API_BASE = "https://public-ubiservices.ubi.com"
UBI_SESSIONS_URL = f"{UBI_API_BASE}/v3/profiles/sessions"
UBI_PROFILE_URL = f"{UBI_API_BASE}/v3/profiles/me"

def _handle_auth_errors(func):
    """Decorator to handle common authentication errors."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except aiohttp.ClientResponseError as error:
            status = error.status
            if status == 400:
                raise AuthenticationRequired("Bad request during authentication")
            elif status == 401:
                raise AuthenticationRequired("Token expired or invalid")
            elif status == 403:
                raise AccessDenied("Access denied during authentication")
            raise UnknownError(f"Unexpected status code: {status}")
    return wrapper


class BackendClient:
    def __init__(self, plugin):
        self._plugin = plugin
        self._auth_lost_callback = None
        
        # Auth state
        self.token = None
        self.session_id = None
        self.refresh_token = None
        self.refresh_time = None
        self.user_id = None
        self.user_name = None
        self.sso_id = None
        
        # State flags
        self._refresh_lock = asyncio.Lock()
        self._keepalive_task = None
        self._connection_stable = True

        self._session = self._create_session()
        self._http_client = HttpClient(self._session)
        self._start_keepalive()

    def _create_session(self):
        """Create and configure HTTP session."""
        connector = create_tcp_connector(limit=30, keepalive_timeout=60)
        headers = {
            "User-Agent": CHROME_USERAGENT,
            "Connection": "keep-alive",
            "Accept": "*/*",
        }
        return create_client_session(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=120),
            cookie_jar=None,
            headers=headers
        )

    def _start_keepalive(self):
        """Start the keepalive background task."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self._keepalive_task = asyncio.ensure_future(self._connection_keepalive())
        except Exception:
            pass

    def _cache_id(self, data, api_key, data_key, attr_name, cache_key, current_time):
        """Cache an ID value."""
        if api_key not in data or getattr(self, attr_name):
            return
        id_value = data[api_key]
        log.info(f"Found {data_key}: {id_value}")
        self._plugin.persistent_cache[cache_key] = json.dumps({data_key: id_value, "timestamp": current_time})
        self._plugin.push_cache()
        setattr(self, attr_name, id_value)

    async def get_app_id(self):
        return UBISOFT_APPID

    async def get_genome_id(self):
        return UBISOFT_GENOMEID

    async def ensure_app_id_header(self):
        """Ensure the Ubi-AppId header is set."""
        if not self._session.headers.get('Ubi-AppId'):
            app_id = UBISOFT_APPID
            self._session.headers['Ubi-AppId'] = app_id
        return self._session.headers['Ubi-AppId']

    async def __aenter__(self):
        await self.ensure_app_id_header()
        return self

    async def close(self):
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
        
        async with self._refresh_lock:
            pass  # Wait for any pending refresh
        await self._session.close()

    def set_auth_lost_callback(self, callback):
        self._auth_lost_callback = callback

    def is_authenticated(self):
        return self.token is not None

    def _build_headers(self, *, include_auth=False, extra=None):
        """Build request headers with optional auth."""
        headers = {
            "User-Agent": CHROME_USERAGENT,
            "Accept": "*/*",
        }
        headers["Ubi-AppId"] = UBISOFT_APPID
        headers["Ubi-GenomeId"] = UBISOFT_GENOMEID
        
        if include_auth:
            if self.token:
                headers["Authorization"] = f"Ubi_v1 t={self.token}"
            if self.session_id:
                headers["Ubi-SessionId"] = self.session_id
            if self.sso_id:
                headers["Ubi-SsoId"] = self.sso_id
        
        if extra:
            headers.update({k: v for k, v in extra.items() if v is not None})
        return headers

    def _update_session_headers(self):
        """Update session headers with current auth state."""
        updates = self._build_headers(include_auth=True)
        for key, value in updates.items():
            self._session.headers[key] = value

    async def _do_request(self, method, *args, **kwargs):
        """Wrapper around http_client.do_request."""
        return await self._http_client.do_request(
            method, *args,
            cached_app_id=UBISOFT_APPID,
            sso_id=self.sso_id,
            **kwargs
        )

    async def _auth_request(self, method, url, *, token_prefix="Ubi_v1", use_remember_me=False, **kwargs):
        """Perform an authenticated request to session endpoints."""
        token = self.refresh_token if use_remember_me else self.token
        prefix = "rm_v1" if use_remember_me else token_prefix
        
        headers = {
            "Authorization": f"{prefix} t={token}",
            "Ubi-AppId": UBISOFT_APPID,
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US;en;q=0.5",
            "Host": "public-ubiservices.ubi.com",
        }
        if self.session_id and not use_remember_me:
            headers["Ubi-SessionId"] = self.session_id
        if UBISOFT_GENOMEID:
            headers["Ubi-GenomeId"] = UBISOFT_GENOMEID
        if use_remember_me:
            headers.update({"Origin": "https://connect.cdn.ubisoft.com", "Referer": "https://connect.cdn.ubisoft.com"})
        
        headers.update(kwargs.pop('extra_headers', {}))
        return await self._do_request(method, url, headers=headers, **kwargs)

    def _should_refresh_token(self):
        """Check if token should be refreshed."""
        if not self.refresh_token:
            return False
        try:
            refresh_time_int = int(self.refresh_time) if self.refresh_time else 0
        except (ValueError, TypeError):
            return False
        
        if refresh_time_int <= 0:
            return False
        return int(datetime.now().timestamp()) > (refresh_time_int - REFRESH_BUFFER_SECONDS)

    async def _refresh_auth(self):
        """Refresh authentication tokens with proper locking."""
        async with self._refresh_lock:
            await self._do_refresh()

    async def _do_refresh(self):
        """Execute token refresh logic."""
        # Try PUT method first (session refresh)
        if await self._try_session_refresh('put'):
            return

        # Try POST with current ticket
        try:
            await self._refresh_via_post(use_remember_me=False)
            return
        except Exception as e:
            log.debug(f"Ticket refresh failed: {e}")

        # Fall back to remember-me token
        if self.refresh_token:
            await self._refresh_via_post(use_remember_me=True)
            await self._refresh_via_post(use_remember_me=False)
        else:
            raise AuthenticationRequired("No refresh token available")

    async def _try_session_refresh(self, method='put'):
        """Try to refresh via session endpoint."""
        if not all([self.token, self.session_id, self.user_id]):
            return False
        try:
            extra = {"Referer": "https://store.ubi.com/upc/login", "Origin": "https://store.ubi.com"}
            response = await self._auth_request(method, UBI_SESSIONS_URL, json={"rememberMe": True}, extra_headers=extra)
            if response and response.get('ticket'):
                self._apply_auth_response(response)
                self._plugin.store_credentials(self.get_credentials())
                log.info(f"Session refresh via {method.upper()} successful")
                return True
        except Exception as e:
            log.debug(f"Session refresh via {method.upper()} failed: {e}")
        return False

    @_handle_auth_errors
    async def _refresh_via_post(self, *, use_remember_me=False):
        """Refresh using POST to sessions endpoint."""
        label = "remember-me" if use_remember_me else "ticket"
        log.debug(f"Refreshing via {label}")
        
        payload = {"rememberMe": True} if use_remember_me else None
        response = await self._auth_request('post', UBI_SESSIONS_URL, use_remember_me=use_remember_me, json=payload)
        
        if not response:
            raise UnknownError("Empty response from authentication server")
        
        await self._handle_auth_response(response)
        self._plugin.store_credentials(self.get_credentials())
        log.debug(f"{label.capitalize()} refresh successful")

    def _apply_auth_response(self, response):
        """Apply authentication response to state."""
        self.token = response['ticket']
        self.session_id = response.get('sessionId', self.session_id)
        self.user_id = response.get('userId', self.user_id)
        if response.get('rememberMeTicket'):
            self.refresh_token = response['rememberMeTicket']
        
        expiration = response.get('expiration')
        if expiration:
            self.refresh_time = self._parse_expiration(expiration)
        
        self._update_session_headers()

    def _parse_expiration(self, expiration_str):
        """Parse expiration timestamp."""
        try:
            exp = expiration_str[:26] + 'Z'
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    return int(datetime.strptime(exp, fmt).timestamp())
                except ValueError:
                    continue
        except Exception:
            pass
        return int(time.time()) + 3600

    async def _handle_auth_response(self, response):
        """Handle full authorization response with time calculation."""
        server_time = dateutil.parser.parse(response['serverTime'])
        expiration = dateutil.parser.parse(response['expiration'])
        refresh_time = datetime.now() + (expiration - server_time)
        response['refreshTime'] = round(refresh_time.timestamp())
        await self.restore_credentials(response, refresh_remember_me=False)

    async def restore_credentials(self, data, refresh_remember_me=True):
        """Restore credentials from data."""
        self.token = data['ticket']
        self.session_id = data['sessionId']
        self.user_id = data['userId']
        self.user_name = data.get('username', self.user_name)
        self.refresh_time = data.get('refreshTime', '0')
        if data.get('rememberMeTicket'):
            self.refresh_token = data['rememberMeTicket']

        if refresh_remember_me and self.refresh_token:
            await self._refresh_via_post(use_remember_me=True)
        
        self._update_session_headers()
        
        if not self._keepalive_task or self._keepalive_task.done():
            try:
                self._keepalive_task = asyncio.ensure_future(self._connection_keepalive())
            except Exception:
                pass

    def get_credentials(self):
        """Get current credentials."""
        creds = {
            "ticket": self.token,
            "sessionId": self.session_id,
            "rememberMeTicket": self.refresh_token,
            "userId": self.user_id,
            "refreshTime": self.refresh_time
        }
        if self.user_name:
            creds["username"] = self.user_name
        return creds

    async def authorise_with_stored_credentials(self, credentials):
        """Authorize using stored credentials."""
        await self.restore_credentials(credentials)
        user_data = await self.get_user_data() if not (self.user_name and self.user_id) else {"username": self.user_name, "userId": self.user_id}
        
        try:
            asyncio.ensure_future(self._try_session_refresh('put'))
            self._plugin.store_credentials(self.get_credentials())
            return user_data
        except Exception as e:
            log.error(f"Error starting token refresh: {e}")
            raise AuthenticationRequired()

    async def authorise_with_local_storage(self, storage_jsons):
        """Authorize using local browser storage data."""
        user_data = {}
        keys = ['userId', 'nameOnPlatform', 'ticket', 'rememberMeTicket', 'sessionId']
        for json_ in storage_jsons:
            for key in keys:
                if key in json_:
                    user_data[key] = json_[key]

        user_data['userId'] = user_data.pop('userId')
        user_data['username'] = user_data.pop('nameOnPlatform')

        await self.restore_credentials(user_data)
        await self.post_sessions()
        self._plugin.store_credentials(self.get_credentials())
        return user_data

    async def _connection_keepalive(self):
        """Background task to keep connection alive."""
        while True:
            try:
                if not self.token:
                    await asyncio.sleep(1)
                    continue

                await asyncio.sleep(5 if not self._connection_stable else 0)

                # Check if refresh needed
                now = int(time.time())
                try:
                    refresh_time_int = int(self.refresh_time) if self.refresh_time else now + 3600
                except (ValueError, TypeError):
                    refresh_time_int = now + 3600

                if refresh_time_int - now < KEEPALIVE_CHECK_THRESHOLD:
                    try:
                        await self._refresh_auth()
                        log.info("Preemptive token refresh successful")
                    except Exception as e:
                        log.warning(f"Preemptive refresh failed: {e}")

                # Ping
                try:
                    await self._do_request('get', UBI_PROFILE_URL, headers={'Ubi-AppId': UBISOFT_APPID})
                    self._connection_stable = True
                except Exception:
                    self._connection_stable = False

                jitter = (int(time.time()) % (2 * KEEPALIVE_JITTER + 1)) - KEEPALIVE_JITTER
                await asyncio.sleep(KEEPALIVE_INTERVAL + jitter)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning(f"Keepalive error: {e}")
                await asyncio.sleep(60)

    async def get_user_data(self):
        """Get user data from Ubisoft API."""
        try:
            await self.ensure_app_id_header()
            headers = self._build_headers(include_auth=True, extra={
                'Content-Type': 'application/json',
                'Ubi-RequestedPlatformType': 'uplay',
                'Origin': 'https://connect.cdn.ubisoft.com',
            })
            
            user_data = await self._do_request('get', UBI_PROFILE_URL, add_to_headers=headers)
            if user_data:
                self.user_id = user_data.get('userId')
                self.user_name = user_data.get('username')
                return user_data
        except Exception as e:
            log.error(f"Error fetching user data: {e}")
        return {"username": self.user_name, "userId": self.user_id}

    async def get_friends(self):
        return await self._do_request('get', 'https://api-ubiservices.ubi.com/v2/profiles/me/friends')

    async def get_entitlements(self):
        await self._refresh_auth()
        headers = self._build_headers(include_auth=True, extra={'ubi-localecode': 'en-US'})
        return await self._do_request('get', f'{UBI_API_BASE}/v1/profiles/me/global/ubiconnect/entitlement/api/entitlements', headers=headers)

    async def get_game_stats(self, space_id):
        headers = {'Ubi-RequestedPlatformType': "uplay", 'Ubi-LocaleCode': "en-US"}
        try:
            return await self._do_request('get', f"{UBI_API_BASE}/v1/profiles/{self.user_id}/statscard?spaceId={space_id}", add_to_headers=headers)
        except UnknownError:
            return {}

    async def get_applications(self, spaces):
        space_string = ','.join(s for s in spaces)
        return await self._do_request('get', f"{UBI_API_BASE}/v1/spaces/global/ubiconnect/games/api/catalog?spaceIds={space_string}", add_to_headers={'Ubi-RequestedPlatformType': 'uplay'})

    async def get_configuration(self):
        return await self._do_request('get', f'{UBI_API_BASE}/v1/spaces/7e8070f7-8f76-4122-8ffc-63b361c3ab9e/parameters')

    async def post_sessions(self):
        return await self._do_request('post', UBI_SESSIONS_URL)

    async def get_subscription(self):
        """Get subscription status."""
        if not self.token:
            return None
        try:
            await self._try_session_refresh('put')
            headers = self._build_headers(include_auth=True, extra={'Content-Type': 'application/json'})
            api = await self._do_request('get', f"https://ess.ubi.com/v2/account/{self.user_id}?fields[]=currentSubscription&subscriptionType=ibex", add_to_headers=headers)
            
            sub = api.get('currentSubscription')
            if sub:
                log.info("Subscription found")
                return api.get("subscriptionType", "premium")
            return None
        except Exception as e:
            log.info(f"Subscription check failed: {e}")
            return None

    async def get_subscription_games(self):
        """Get subscription games."""
        try:
            if not await self.get_subscription():
                return []
            
            games = await self._do_request('get', f"{UBI_API_BASE}/v1/applications/global/webservices/ubisoftplus/vault/products?storefront=us", 
                                           add_to_headers={'Ubi-RequestedPlatformType': 'uplay', 'Accept': 'application/json'})
            return games or []
        except AuthenticationRequired:
            if self._auth_lost_callback:
                self._auth_lost_callback()
            return []
        except Exception as e:
            log.warning(f"Failed to get subscription games: {e}")
            return []
