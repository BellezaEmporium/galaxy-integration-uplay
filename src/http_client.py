import json
import logging as log
import aiohttp
from galaxy.api.errors import AuthenticationRequired, AccessDenied, UnknownError
from galaxy.http import handle_exception
from consts import UBISOFT_APPID

# Constants
UBISOFT_DOMAINS = {'connect.ubisoft.com', 'store.ubi.com'}
UBIAPI_DOMAINS = {'api-ubiservices.ubi.com', 'public-ubiservices.ubi.com'}

class HttpClient:
    """Low-level HTTP client for Ubisoft API requests."""
    
    def __init__(self, session):
        """
        Args:
            session: aiohttp.ClientSession instance
        """
        self._session = session

    async def request(self, method, url, *args, **kwargs):
        """Perform HTTP request with error handling."""
        with handle_exception():
            try:
                return await self._session.request(method, url, *args, **kwargs)
            except aiohttp.ClientResponseError as error:
                self._handle_http_error(error)
                raise error

    def _handle_http_error(self, error):
        """Handle HTTP error responses."""
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

    def _apply_request_headers(self, kwargs):
        """Apply and merge request headers."""
        if 'headers' not in kwargs:
            kwargs['headers'] = self._session.headers.copy()
        
        if 'add_to_headers' in kwargs:
            for header, value in kwargs['add_to_headers'].items():
                if header is not None:
                    if value is not None:
                        kwargs['headers'][header] = value
                    else:
                        kwargs['headers'].pop(header, None)
            kwargs.pop('add_to_headers')
        
        # Clean up None values
        for key in list(kwargs['headers'].keys()):
            if kwargs['headers'][key] is None:
                del kwargs['headers'][key]

    async def _ensure_request_headers(self, kwargs, cached_app_id, sso_id):
        """Ensure required headers are present for the request."""
        if 'Ubi-AppId' not in kwargs['headers'] or not kwargs['headers']['Ubi-AppId']:
            kwargs['headers']['Ubi-AppId'] = UBISOFT_APPID
        
        url_str = kwargs['headers'].get('_url', '')
        if sso_id and any(domain in url_str for domain in UBISOFT_DOMAINS):
            kwargs['headers']['Ubi-SsoId'] = sso_id
        
        if any(domain in url_str for domain in UBIAPI_DOMAINS):
            if 'Content-Type' not in kwargs['headers']:
                kwargs['headers']['Content-Type'] = 'application/json'
                
    def _is_html_content(self, content_type):
        """Check if content type indicates HTML."""
        return 'text/html' in content_type

    async def _try_extract_json(self, text_content):
        """Try to extract and parse JSON from text content."""
        text_stripped = text_content.strip()
        if text_stripped.startswith('{') and text_stripped.endswith('}'):
            try:
                return json.loads(text_stripped)
            except json.JSONDecodeError:
                log.warning("Failed to parse JSON from text content")
        return None

    async def _handle_response_content(self, r, content_type):
        """Handle response based on content type."""
        if self._is_html_content(content_type):
            text_content = await r.text()
            log.debug(f"Received HTML. Content: {text_content[:200]}...")
            
            json_data = await self._try_extract_json(text_content)
            if json_data:
                log.info("Successfully extracted JSON from HTML response")
                return json_data
            
            if any(marker in str(r.url) for marker in ['loadingScreen', 'login', 'connect']):
                log.warning("Received authentication page instead of expected data")
                raise AuthenticationRequired("Authentication redirect detected")
            
            if 'store.ubi.com' in str(r.url):
                log.warning("Received HTML from store.ubi.com, returning empty object")
                return {}
        
        try:
            return await r.json()
        except (aiohttp.ContentTypeError, json.JSONDecodeError) as e:
            log.warning(f"Failed to decode JSON response: {str(e)}")
            if r.status == 204:
                return {}
            if 'store.ubi.com' in str(r.url):
                log.warning("Failed to parse JSON from store.ubi.com, returning empty object")
                return {}
            raise UnknownError(f"Failed to parse JSON from response (status {r.status})")

    async def do_request(self, method, *args, cached_app_id=None, sso_id=None, **kwargs):
        """
        Perform HTTP request with automatic header management and response handling.
        
        Args:
            method: HTTP method (get, post, put, etc.)
            *args: URL and other positional args
            cached_app_id: Ubi-AppId to use
            sso_id: Ubi-SsoId to use
            **kwargs: Additional request kwargs (add_to_headers, etc.)
        
        Returns:
            Parsed JSON response
        """
        self._apply_request_headers(kwargs)
        
        url_str = args[0] if args else kwargs.get('url', '')
        kwargs['headers']['_url'] = url_str
        
        await self._ensure_request_headers(kwargs, cached_app_id, sso_id)
        del kwargs['headers']['_url']

        try:
            r = await self.request(method, *args, **kwargs)
            log.debug(f"Response status: {getattr(r,'status','?')} {getattr(r,'method',getattr(r,'_method',''))} {getattr(r,'url','')}")
            
            if r.status == 401:
                await r.read()
                raise AuthenticationRequired("Unauthorized (401)")
            if r.status == 403:
                await r.read()
                raise AccessDenied("Forbidden (403)")
            if 500 <= r.status < 600:
                log.warning(f"Server error {r.status} for {getattr(r,'url','')}")
            
            content_type = r.headers.get('Content-Type', '')
            log.debug(f"Response content type: {content_type}")
            return await self._handle_response_content(r, content_type)
        
        except aiohttp.ClientConnectorError as e:
            log.error(f"Connection error: {str(e)}")
            raise UnknownError(f"Connection error: {str(e)}")
        except Exception as e:
            if not isinstance(e, (AccessDenied, AuthenticationRequired, UnknownError)):
                log.error(f"Unexpected error in do_request: {repr(e)}")
                raise UnknownError(f"Request failed: {str(e)}")
            raise
