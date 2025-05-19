from datetime import datetime
import json
import logging as log
from galaxy.http import handle_exception, create_tcp_connector, create_client_session
import dateutil.parser

import aiohttp
import asyncio
import time

from galaxy.api.errors import AuthenticationRequired, AccessDenied, UnknownError

from consts import CHROME_USERAGENT

class BackendClient():
    def __init__(self, plugin):
        self._plugin = plugin        
        self._auth_lost_callback = None
        self.token = None
        self.session_id = None
        self.refresh_token = None
        self.refresh_time = None
        self._cached_app_id = None
        self.user_id = None
        self.user_name = None
        self.sso_id = None
        self.__refresh_in_progress = False
        connector = create_tcp_connector(limit=30)
        headers = {
            "User-Agent": CHROME_USERAGENT
        }
        self._session = create_client_session(connector=connector, timeout=aiohttp.ClientTimeout(total=120),
                                              cookie_jar=None, headers=headers)

    async def get_app_id(self):
        """Fetch the latest app ID from cache or from Ubisoft's SDK"""
        default_app_id = "314d4fef-e568-454a-ae06-43e3bece12a6"
        
        cached_data = self._plugin.persistent_cache.get('ubisoft_app_id')
        current_time = int(time.time())
        
        if cached_data:
            try:
                cached = json.loads(cached_data)
                if cached.get('app_id') and (current_time - cached.get('timestamp', 0) < 604800):
                    self._cached_app_id = cached['app_id']
                    log.info(f"Using cached AppId: {self._cached_app_id}")
                    return self._cached_app_id
            except Exception as e:
                log.warning(f"Error parsing cached AppId: {str(e)}")
        
        try:
            url = "https://store.ubisoft.com/on/demandware.store/Sites-us_ubisoft-Site/en-US/UPlayConnect-GetAPISettingsJson"
            async with self._session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'app-id' in data:
                        app_id = data['app-id']
                        log.info(f"Dynamically found AppId: {app_id}")
                        
                        # Met à jour le cache
                        cache_data = {
                            "app_id": app_id,
                            "timestamp": current_time
                        }
                        self._plugin.persistent_cache['ubisoft_app_id'] = json.dumps(cache_data)
                        self._plugin.push_cache()
                        self._cached_app_id = app_id
                        
                        return app_id

            log.warning("Could not extract AppId, using default")
        except Exception as e:
            log.error(f"Error retrieving AppId: {str(e)}")
        return default_app_id
    
    async def get_genome_id(self):
        """Fetch the latest genome ID from cache or from Ubisoft's SDK"""
        default_genome_id = "314d4fef-e568-454a-ae06-43e3bece12a6"
        cached_data = self._plugin.persistent_cache.get('ubisoft_genome_id')
        current_time = int(time.time())
        if cached_data:
            try:
                cached = json.loads(cached_data)
                if cached.get('genome_id') and (current_time - cached.get('timestamp', 0) < 604800):
                    self._cached_genome_id = cached['genome_id']
                    log.info(f"Using cached GenomeId: {self._cached_genome_id}")
                    return self._cached_genome_id
            except Exception as e:
                log.warning(f"Error parsing cached GenomeId: {str(e)}")
        try:
            url = "https://store.ubisoft.com/on/demandware.store/Sites-us_ubisoft-Site/en-US/UPlayConnect-GetAPISettingsJson"
            async with self._session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'genome-id' in data:
                        genome_id = data['genome-id']
                        log.info(f"Dynamically found GenomeId: {genome_id}")
                        cache_data = {
                            "genome_id": genome_id,
                            "timestamp": current_time
                        }
                        self._plugin.persistent_cache['ubisoft_genome_id'] = json.dumps(cache_data)
                        self._plugin.push_cache()
                        self._cached_genome_id = genome_id
                        return genome_id
            log.warning("Could not extract GenomeId, using default")
        except Exception as e:
            log.error(f"Error retrieving GenomeId: {str(e)}")
        return default_genome_id

    async def ensure_app_id_header(self):
        """Ensure the Ubi-AppId header is set with the current app ID"""
        if 'Ubi-AppId' not in self._session.headers or not self._session.headers['Ubi-AppId']:
            if self._cached_app_id:
                app_id = self._cached_app_id
                log.info(f"Using cached AppId for header: {app_id}")
            else:
                app_id = await self.get_app_id()
            self._session.headers.update({'Ubi-AppId': app_id})
            log.info(f"Updated Ubi-AppId header to: {app_id}")
        return self._session.headers['Ubi-AppId']

    async def __aenter__(self):
        """Setup session when using as async context manager"""
        await self.ensure_app_id_header()
        return self

    async def close(self):
        # If closing is attempted while plugin is inside refresh workflow then give it a chance to finish it.
        if self.__refresh_in_progress:
            time.sleep(1.5)
        await self._session.close()    
        
    async def request(self, method, url, *args, **kwargs):
        with handle_exception():
            try:
                return await self._session.request(method, url, *args, **kwargs)
            except aiohttp.ClientResponseError as error:
                if error.status >= 500:
                    log.warning(
                        "Got status %d while performing %s request for %s",
                        error.status, error.request_info.method, str(error.request_info.url)
                    )
                elif error.status == 401:
                    log.warning(
                        "Unauthorized (401) while performing %s request for %s",
                        error.request_info.method, str(error.request_info.url)
                    )
                    raise AuthenticationRequired("Unauthorized access")
                elif error.status == 403:
                    log.warning(
                        "Forbidden (403) while performing %s request for %s",
                        error.request_info.method, str(error.request_info.url)
                    )
                    raise AccessDenied("Access denied")
                raise error

    def set_auth_lost_callback(self, callback):
        self._auth_lost_callback = callback

    def is_authenticated(self):
        return self.token is not None
    
    async def _do_request(self, method, *args, **kwargs):
        if 'headers' not in kwargs:
            log.info("No headers in kwargs, using session headers")
            kwargs['headers'] = self._session.headers.copy()
        if 'add_to_headers' in kwargs:
            for header, value in kwargs['add_to_headers'].items():
                if value is not None:
                    kwargs['headers'][header] = value
                    log.debug(f"Added header: {header}={value[:20] if isinstance(value, str) else value}...")
                else:
                    if header in kwargs['headers']:
                        del kwargs['headers'][header]
                        log.debug(f"Removed header: {header} (value was None)")
            kwargs.pop('add_to_headers')
        
        if 'Ubi-AppId' not in kwargs['headers'] or not kwargs['headers']['Ubi-AppId']:
            app_id = await self.ensure_app_id_header()
            kwargs['headers']['Ubi-AppId'] = app_id
            log.debug(f"Added missing Ubi-AppId header: {app_id}")
        
        url_str = args[0] if args else kwargs.get('url', '')
        if self.sso_id and any(domain in url_str for domain in ['connect.ubisoft.com', 'store.ubi.com']):
            kwargs['headers']['Ubi-SsoId'] = self.sso_id
            log.debug(f"Added Ubi-SsoId header: {self.sso_id}")
        
        if any(ubiapi in args[0] for ubiapi in ['api-ubiservices.ubi.com', 'public-ubiservices.ubi.com']):
            if 'Content-Type' not in kwargs['headers']:
                kwargs['headers']['Content-Type'] = 'application/json'
                log.debug("Added missing Content-Type header")
        
        headers_to_remove = [key for key, value in kwargs['headers'].items() if value is None]
        for key in headers_to_remove:
            del kwargs['headers'][key]

        try:
            r = await self.request(method, *args, **kwargs)
            log.info(f"Response status: {r}")
            try:
                content_type = r.headers.get('Content-Type', '')
                log.debug(f"Response content type: {content_type}")
                
                # If we receive HTML when expecting JSON, it may be a login/redirect page
                if 'text/html' in content_type:
                    text_content = await r.text()
                    log.debug(f"Received HTML when expecting JSON. Content: {text_content[:200]}...")
                    
                    # Check if the HTML actually contains a JSON response
                    text_content_stripped = text_content.strip()
                    if text_content_stripped.startswith('{') and text_content_stripped.endswith('}'):
                        log.info(f"HTML response appears to contain JSON: {text_content_stripped}")
                        try:
                            json_data = json.loads(text_content_stripped)
                            log.info(f"Successfully extracted JSON from HTML response: {json_data}")
                            return json_data
                        except json.JSONDecodeError:
                            log.warning("Failed to parse JSON from HTML content")
                    
                    # If the URL contains certain authentication redirect markers
                    if any(auth_marker in str(r.url) for auth_marker in ['loadingScreen', 'login', 'connect']):
                        log.warning("Received authentication page instead of expected data")
                        raise AuthenticationRequired("Authentication redirect detected")
                    
                     # For certain Ubisoft store URLs, return an empty object instead of raising
                    if 'store.ubi.com' in str(r.url):
                        log.warning("Received HTML from store.ubi.com, returning empty object")
                        return {}
                
                # Try to decode as JSON
                j = await r.json()
                return j

            except (aiohttp.ContentTypeError, json.JSONDecodeError) as e:
                log.warning(f"Failed to decode JSON response: {str(e)}")
                content = await r.text()

                # Check if the content is a JSON string embedded in HTML
                if 'text/html' in content_type and content.strip().startswith('{') and content.strip().endswith('}'):
                    log.info("Found JSON content in HTML response, attempting to parse")
                    try:
                        j = json.loads(content)
                        return j
                    except json.JSONDecodeError:
                        log.warning("Failed to parse embedded JSON content")

                if r.status == 204:  # No content
                    return {}

            # For store requests, return empty object instead of raising
            if 'store.ubi.com' in str(r.url):
                log.warning("Failed to parse JSON from store.ubi.com, returning empty object")
                return {}
            raise UnknownError(f"Failed to parse JSON from response (status {r.status})")
        
        except aiohttp.ClientConnectorError as e:
            log.error(f"Connection error: {str(e)}")
            raise UnknownError(f"Connection error: {str(e)}")
        except Exception as e:
            if not isinstance(e, (AccessDenied, AuthenticationRequired, UnknownError)):
                log.error(f"Unexpected error in _do_request: {repr(e)}")
                raise UnknownError(f"Request failed: {str(e)}")
            raise

    async def _do_request_safe(self, method, *args, **kwargs):
        result = {}
        try:
            refresh_needed = False
            try:
                refresh_time_int = int(self.refresh_time) if self.refresh_time is not None else 0
            except Exception:
                refresh_time_int = 0
            now = int(datetime.now().timestamp())
            if self.refresh_token:
                log.debug(f'rememberMeTicket expiration time: {str(self.refresh_time)}')
                if refresh_time_int > 0:
                    refresh_needed = now > refresh_time_int
                else:
                    log.warning(f"refresh_time incohérent ou absent ({self.refresh_time}), pas de refresh automatique.")
                    refresh_needed = False
            if refresh_needed:
                log.info("Token expiré, rafraîchissement en cours...")
                await self._refresh_auth()
                result = await self._do_request(method, *args, **kwargs)
            else:
                try:
                    result = await self._do_request(method, *args, **kwargs)
                except (AccessDenied, AuthenticationRequired):
                    # fallback for another reason than expired time or wrong calculation due to changing time zones
                    log.debug('Fallback refresh')
                    if not self.refresh_token:
                        log.warning("No refresh token present, possibly unchecked remember me when connecting plugin")
                    await self._refresh_auth()
                    result = await self._do_request(method, *args, **kwargs)
        except (AccessDenied, AuthenticationRequired) as e:
            log.debug(f"Unable to refresh authentication calling auth lost: {repr(e)}")
            if self._auth_lost_callback:
                self._auth_lost_callback()
            raise
        except Exception as e:
            log.debug("Refresh workflow has failed:" + repr(e))
            raise
        return result
    
    async def _do_options_request(self, url="https://public-ubiservices.ubi.com/v3/profiles/sessions", origin="https://connect.ubisoft.com", referer=None):
        app_id = await self.ensure_app_id_header()
        
        if not referer:
            if "connect.ubisoft.com" in origin:
                referer = f"https://connect.ubisoft.com/login?appId={app_id}"
            elif "store.ubi.com" in origin:
                referer = "https://store.ubi.com/upc/login"
            else:
                referer = origin
        
        headers = {
            "origin": origin,
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization,ubi-appid,ubi-localecode,ubi-profileid,ubi-sessionid,x-platform-appid",
            "user-agent": CHROME_USERAGENT,
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "sec-fetch-dest": "empty",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "en-US,en;q=0.9"
        }
        
        log.debug(f"OPTIONS request to {url} with headers: {headers}")
        
        try:
            async with self._session.request('OPTIONS', url, headers=headers) as response:
                status = response.status
                log.debug(f"OPTIONS request status: {status}")
                response_headers = dict(response.headers)
                log.debug(f"OPTIONS response headers: {response_headers}")
                return status == 200
        except Exception as e:
            log.warning(f"OPTIONS request failed: {repr(e)}")
            return False
    
    async def _refresh_auth(self):
        if self.__refresh_in_progress:
            log.info('Refreshing already in progress.')
            while self.__refresh_in_progress:
                await asyncio.sleep(0.2)
        else:
            self.__refresh_in_progress = True
            try:
                try:
                    log.debug("Attempting to refresh via PUT /v3/profiles/sessions (refresh_token_via_session)")
                    put_success = await self.refresh_token_via_session()
                    if put_success:
                        self._plugin.store_credentials(self.get_credentials())
                        log.debug("Successfully refreshed via PUT /v3/profiles/sessions")
                        return
                    log.debug("Falling back to legacy refresh methods")
                    await self._refresh_ticket()
                    self._session.headers.update({
                        "authorization": f"ubi_v1 t={self.token}",
                        "ubi-sessionid": self.session_id,
                        "user-agent": CHROME_USERAGENT,
                        "accept": "*/*",
                    })
                    self._plugin.store_credentials(self.get_credentials())
                    log.debug("Successfully refreshed using ticket")
                except Exception as e:
                    log.debug(f"Failed to refresh using ticket: {repr(e)}")
                    if not self.refresh_token:
                        log.warning("No refresh token available, authentication may fail")
                        raise
                    log.debug("Attempting to refresh using remember me token")
                    await self._refresh_remember_me()
                    log.debug("Successfully refreshed using remember me token")
                    await self._refresh_ticket()
                    self._plugin.store_credentials(self.get_credentials())
                    log.debug("Successfully refreshed ticket after remember me refresh")
            except Exception as e:
                log.error(f"All refresh attempts failed: {repr(e)}")
                raise
            finally:
                self.__refresh_in_progress = False    

    async def _refresh_remember_me(self):
        log.debug('Refreshing rememberMeTicket')
        await self._do_options_request()
        app_id = await self.get_app_id()
        headers = self._build_auth_headers(
            token=None,
            app_id=app_id,
            content_type='application/json',
            accept='*/*',
            origin='https://connect.cdn.ubisoft.com',
            referer='https://connect.cdn.ubisoft.com',
            extra={
                'Authorization': f"rm_v1 t={self.refresh_token}",
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US;en;q=0.5',
                'Host': 'public-ubiservices.ubi.com',
            }
        )
        try:
            j = await self._do_request(
                'post',
                'https://public-ubiservices.ubi.com/v3/profiles/sessions',
                headers=headers,
                json={"rememberMe": True}
            )
        except aiohttp.ClientResponseError as error:
            log.warning(f"Error during remember me refresh: {error.status} - {error}")
            if error.status in (400, 401):
                raise AuthenticationRequired("Remember me token expired or invalid")
            elif error.status == 403:
                raise AccessDenied("Access denied during remember me refresh")
            else:
                raise UnknownError(f"Unexpected status code: {error.status}")
        except Exception as e:
            log.error(f"Unexpected exception during remember me refresh: {repr(e)}")
            raise
        if not j:
            log.error("Empty response received during remember me refresh")
            raise UnknownError("Empty response from authentication server")
        self._handle_authorization_response(j)

    async def _refresh_ticket(self):
        log.debug('Refreshing ticket')
        await self._do_options_request()
        app_id = await self.get_app_id()
        headers = self._build_auth_headers(
            token=self.token,
            app_id=app_id,
            content_type='application/json',
            accept='*/*',
            origin='https://connect.cdn.ubisoft.com',
            referer='https://connect.cdn.ubisoft.com',
            extra={
                'Accept-Encoding': 'gzip, deflate, br',
                'Accept-Language': 'en-US;en;q=0.5',
                'Host': 'public-ubiservices.ubi.com',
            }
        )
        try:
            j = await self._do_request(
                'post',
                'https://public-ubiservices.ubi.com/v3/profiles/sessions',
                headers=headers)
        except aiohttp.ClientResponseError as error:
            if error.status == 400:
                log.warning(f"Bad request during ticket refresh: {error}")
                raise AuthenticationRequired("Bad request during authentication")
            elif error.status == 401:
                log.warning(f"Unauthorized during ticket refresh: {error}")
                raise AuthenticationRequired("Token expired or invalid")
            elif error.status == 403:
                log.warning(f"Forbidden during ticket refresh: {error}")
                raise AccessDenied("Access denied during authentication")
            else:
                log.warning(f"Unexpected error during ticket refresh: {error.status} - {error}")
                raise UnknownError(f"Unexpected status code: {error.status}")
        except Exception as e:
            log.error(f"Unexpected exception during ticket refresh: {repr(e)}")
            raise
        if not j:
            log.error("Empty response received during ticket refresh")
            raise UnknownError("Empty response from authentication server")
        self._handle_authorization_response(j)

    async def refresh_token_via_session(self):
        if not self.token or not self.session_id or not self.user_id:
            log.warning("Cannot refresh token: missing authentication information")
            return False
        try:
            sso_options_url = "https://public-ubiservices.ubi.com/v3/profiles/sessions"
            await self._do_options_request(
                url=sso_options_url,
                origin="https://store.ubi.com",
                referer="https://store.ubi.com/upc/us",
            )
            headers = self._build_auth_headers(
                token=self.token,
                session_id=self.session_id,
                genome_id=await self.get_genome_id(),
                app_id=await self.get_app_id(),
                referer='https://store.ubi.com/upc/login',
                origin='https://store.ubi.com',
            )
            login_url = "https://public-ubiservices.ubi.com/v3/profiles/sessions"
            log.info("Refreshing via sessions...")
            response = await self._do_request('put', login_url, add_to_headers=headers, json={"rememberMe": True})
            if response and response.get('ticket'):
                log.info("Session authenticated successfully")
                self.token = response['ticket']
                self.session_id = response.get('sessionId', self.session_id)
                self.user_id = response.get('userId', self.user_id)
                expiration_str = response.get('expiration')
                if expiration_str:
                    try:
                        expiration_str = expiration_str[:26] + 'Z'
                        self.refresh_time = int(datetime.strptime(expiration_str, "%Y-%m-%dT%H:%M:%S.%fZ").timestamp())
                    except ValueError:
                        expiration_str = expiration_str[:26] + 'Z'
                        self.refresh_time = int(datetime.strptime(expiration_str, "%Y-%m-%dT%H:%M:%SZ").timestamp())
                        self._session.headers.update({
                            "authorization": f"ubi_v1 t={self.token}",
                            "ubi-sessionid": self.session_id
                        })
                return True
            else:
                log.warning(f"Authentication failed: {response}")
                try:
                    await asyncio.sleep(1)
                    alt_login_url = "https://store.ubi.com/on/demandware.store/Sites-us_uplaypc-Site/en_US/UPlayConnect-Login"
                    log.info("Trying alternative store login endpoint...")
                    alt_response = await self._do_request('post', alt_login_url, add_to_headers=headers)
                    if alt_response and alt_response.get('status') == 'success':
                        log.info("Store session authenticated successfully with alternative endpoint")
                        return True
                    else:
                        log.warning(f"Alternative store login failed: {response}")
                        return False
                except Exception as e:
                    log.debug(f"All store authentication methods failed: {repr(e)}")
                return False
        except Exception as e:
            log.error(f"Error authenticating store session: {repr(e)}")
            return False
            
    def _handle_authorization_response(self, j):
        refresh_time = datetime.now() + (dateutil.parser.parse(j['expiration']) - dateutil.parser.parse(j['serverTime']))
        j['refreshTime'] = round(refresh_time.timestamp())
        self.restore_credentials(j)

    def restore_credentials(self, data):
        self.token = data['ticket']
        self.session_id = data['sessionId']
        self.user_id = data['userId']
        if data.get('username'):
            self.user_name = data['username']
        self.refresh_time = data.get('refreshTime', '0')
        if data.get('rememberMeTicket'):
            self.refresh_token = data['rememberMeTicket']
        
        # Assurez-vous que les en-têtes sont exactement formatés comme dans la requête fonctionnelle
        self._session.headers.update({
            "authorization": f"ubi_v1 t={self.token}",
            "ubi-sessionid": self.session_id,
            "user-agent": CHROME_USERAGENT,
            "accept": "*/*",
        })

    def get_credentials(self):
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

    async def get_user_data(self):
        """Get user data from Ubisoft API"""
        try:
            app_id = await self.ensure_app_id_header()
            headers = {
                'Ubi-AppId': app_id,
                'Content-Type': 'application/json',
                'Authorization': f"Ubi_v1 t={self.token}",
                'Ubi-RequestedPlatformType': 'uplay',
                'Origin': 'https://connect.cdn.ubisoft.com',
                'User-Agent': CHROME_USERAGENT,
            }
            
            user_data = await self._do_request('get', 'https://public-ubiservices.ubi.com/v3/profiles/me', add_to_headers=headers)
            
            if user_data:
                self.user_id = user_data.get('userId')
                self.user_name = user_data.get('username')
                return user_data
            else:
                log.warning("Empty response when fetching user data")
                return {"username": self.user_name, "userId": self.user_id}
        except Exception as e:
            log.error(f"Error fetching user data: {repr(e)}")
            return {"username": self.user_name, "userId": self.user_id}

    async def authorise_with_stored_credentials(self, credentials):
        self.restore_credentials(credentials)
        if not self.user_name or not self.user_id:
            user_data = await self.get_user_data()
        else:
            user_data = {"username": self.user_name,
                         "userId": self.user_id}
        asyncio.create_task(self.refresh_token_via_session())
        self._plugin.store_credentials(self.get_credentials())
        return user_data

    async def authorise_with_local_storage(self, storage_jsons):
        user_data = {}
        tasty_storage_values = ['userId', 'nameOnPlatform', 'ticket', 'rememberMeTicket', 'sessionId']
        for json_ in storage_jsons:
            for key in json_:
                if key in tasty_storage_values:
                    user_data[key] = json_[key]

        user_data['userId'] = user_data.pop('userId')
        user_data['username'] = user_data.pop('nameOnPlatform')

        self.restore_credentials(user_data)
        await self.post_sessions()
        self._plugin.store_credentials(self.get_credentials())
        return user_data
    async def get_friends(self):
        return await self._do_request_safe('get', 'https://api-ubiservices.ubi.com/v2/profiles/me/friends')
        
    async def get_entitlements(self):
        """
        Version améliorée qui utilise une approche directe pour simuler exactement 
        la requête d'Insomnia qui fonctionne.
        """
        app_id = await self.get_app_id()
        url = 'https://public-ubiservices.ubi.com/v1/profiles/me/global/ubiconnect/entitlement/api/entitlements'
        
        # Headers exacts, formatés comme dans la requête fonctionnelle
        headers = {
            'host': 'public-ubiservices.ubi.com',
            'authorization': f'ubi_v1 t={self.token}',
            'ubi-appid': app_id,
            'ubi-profileid': self.user_id,
            'ubi-sessionid': self.session_id,
            'user-agent': CHROME_USERAGENT,
            'accept': '*/*',
            'origin': 'https://connect.cdn.ubisoft.com',
            'sec-fetch-site': 'cross-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-language': 'en-US,en;q=0.9',
        }
        
        log.debug(f"get_entitlements call with token: {self.token[:10]}... and session_id: {self.session_id}")
        
        try:
            # Étape 1: Demande OPTIONS (pré-vol CORS)
            options_headers = {
                'origin': 'https://connect.cdn.ubisoft.com',
                'access-control-request-method': 'GET',
                'access-control-request-headers': 'authorization,ubi-appid,ubi-localecode,ubi-profileid,ubi-sessionid,x-platform-appid',
                'user-agent': CHROME_USERAGENT,
                'accept': '*/*',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'cross-site',
                'sec-fetch-dest': 'empty',
                'accept-language': 'en-US,en;q=0.9'
            }
            
            log.debug(f"Sending OPTIONS request to {url}")
            
            # Utilisation directe de ClientSession pour éviter toute modification
            async with aiohttp.ClientSession() as session:
                # Requête OPTIONS
                async with session.options(url, headers=options_headers) as options_response:
                    options_status = options_response.status
                    log.debug(f"OPTIONS response status: {options_status}")
                    if options_status != 200:
                        log.warning(f"OPTIONS request failed with status {options_status}")
                
                # Pause pour simuler le comportement du navigateur
                await asyncio.sleep(0.2)
                
                # Requête GET
                log.debug(f"Sending GET request to {url} with headers: {headers}")
                async with session.get(url, headers=headers) as response:
                    status = response.status
                    log.debug(f"GET response status: {status}")
                    
                    if status == 200:
                        data = await response.json()
                        log.debug(f"Successfully retrieved entitlements data")
                        return data
                    elif status == 401:
                        log.warning(f"Authentication failed (401). Token might be expired.")
                        raise AuthenticationRequired("Authentication token expired or invalid")
                    else:
                        log.warning(f"Request failed with status {status}")
                        content = await response.text()
                        log.debug(f"Response content: {content[:200]}...")
                        raise UnknownError(f"Request failed with status {status}")
                        
        except AuthenticationRequired:
            # Réessayer avec un rafraîchissement de token
            log.warning("Authentication required, attempting to refresh token...")
            try:
                await self._refresh_auth()
                # Réessayer la requête avec le nouveau token
                log.debug("Token refreshed, retrying request")
                return await self.get_entitlements()  # Appel récursif avec le nouveau token
            except Exception as refresh_error:
                log.error(f"Failed to refresh token: {repr(refresh_error)}")
                if self._auth_lost_callback:
                    self._auth_lost_callback()
                raise AuthenticationRequired("Failed to refresh authentication")
        except Exception as e:
            log.error(f"Error during entitlements request: {repr(e)}")
            raise UnknownError(f"Entitlements request failed: {str(e)}")

    async def get_game_stats(self, space_id):
        url = f"https://public-ubiservices.ubi.com/v1/profiles/{self.user_id}/statscard?spaceId={space_id}"
        headers = {
            'Ubi-RequestedPlatformType': "uplay",
            'Ubi-LocaleCode': "en-GB"
        }
        try:
            j = await self._do_request('get', url, add_to_headers=headers)
        except UnknownError: 
            return {}
        return j

    async def get_applications(self, spaces):
        space_string = ','.join(space['spaceId'] for space in spaces)
        headers = {'Ubi-RequestedPlatformType': 'uplay'}
        j = await self._do_request_safe('get', f"https://api-ubiservices.ubi.com/v2/applications?spaceIds={space_string}", add_to_headers=headers)
        return j
    
    async def get_configuration(self):
        r = await self._do_request_safe('get', 'https://public-ubiservices.ubi.com/v1/spaces/7e8070f7-8f76-4122-8ffc-63b361c3ab9e/parameters')
        return r    
    
    async def post_sessions(self):
        j = await self._do_request_safe('post', "https://public-ubiservices.ubi.com/v3/profiles/sessions")
        return j

    async def get_subscription(self):
        try:
            if not self.token:
                log.warning("Not authenticated, cannot check subscription status")
                return None

            store_auth_success = await self.refresh_token_via_session()
            if not store_auth_success:
                log.warning("Failed to authenticate store session, subscription check may fail")
            
            headers = {
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'Authorization': f"Ubi_v1 t={self.token}",
                'Content-Type': 'application/json',
                'Ubi-AppId': await self.get_app_id(),
                'Ubi-SessionId': self.session_id,
            }

            api_url = f"https://ess.ubi.com/v2/account/{self.user_id}?fields[]=currentSubscription&subscriptionType=ibex"
            api = await self._do_request_safe('get', api_url, add_to_headers=headers)
            if 'currentSubscription' in api:
                log.info(f"Found subscription status: {api['currentSubscription']}")
                if api['currentSubscription'] != None:
                    log.info("Subscription found.")
                    return api.get("subscriptionType", "premium")
                else:
                    log.info("No active subscription found.")
                    return None
            else:
                log.warning("No currentSubscription key in API response.")
                return None
        except Exception as e:
            log.info(f"Ubisoft+ subscription check failed: {repr(e)}")
            return None
          
    async def get_subscription_games(self):
        try:
            subscription = await self.get_subscription()
            if not subscription:
                log.info("No active subscription found, skipping games fetch")
                return []
            
            headers = {
                'Ubi-RequestedPlatformType': 'uplay',
                'Accept': 'application/json'
            }
            
            storefront = "us"
            
            log.info(f"Fetching subscription games for storefront: {storefront}")
            sub_games = await self._do_request_safe('get', 
                f"https://public-ubiservices.ubi.com/v1/applications/global/webservices/ubisoftplus/vault/products?storefront={storefront}", 
                add_to_headers=headers
            )
            
            if not sub_games:
                log.warning("Empty response when fetching subscription games")
                return []
                
            log.info(f"Successfully retrieved {len(sub_games)} subscription games")
            return sub_games
        except AuthenticationRequired as e:
            log.warning(f"Authentication required for subscription games: {repr(e)}")
            if self._auth_lost_callback:
                self._auth_lost_callback()
            return []
        except Exception as e:
            log.warning(f"Failed to get subscription games: {repr(e)}")
            return []

    def _build_auth_headers(self, *, token=None, session_id=None, sso_id=None, genome_id=None, app_id=None, referer=None, origin=None, extra=None, content_type='application/json', accept='application/json'):
        headers = {
            'Content-Type': content_type,
            'Accept': accept,
            'User-Agent': CHROME_USERAGENT,
        }
        if app_id or self._cached_app_id:
            headers['Ubi-AppId'] = app_id or self._cached_app_id
        if token:
            headers['Authorization'] = f"Ubi_v1 t={token}"
        if session_id:
            headers['Ubi-SessionId'] = session_id
        if sso_id:
            headers['Ubi-SsoId'] = sso_id
        if genome_id:
            headers['Genomeid'] = genome_id
        if referer:
            headers['Referer'] = referer
        if origin:
            headers['Origin'] = origin
        if extra:
            headers.update(extra)
        # Nettoyage des valeurs None
        return {k: v for k, v in headers.items() if v is not None}
