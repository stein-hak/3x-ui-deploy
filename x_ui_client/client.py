"""
Main 3x-ui API client implementation
"""

import requests
from typing import Optional, Dict, List, Any
from .exceptions import AuthenticationError, APIError, NotFoundError


class XUIClient:
    """Client for interacting with 3x-ui panel API"""

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True):
        """
        Initialize the 3x-ui API client

        Args:
            base_url: Base URL of the 3x-ui panel (e.g., 'http://localhost:2053')
            username: Admin username
            password: Admin password
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self._authenticated = False

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make an API request

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (will be appended to base_url)
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response JSON data

        Raises:
            APIError: If the request fails
        """
        url = f"{self.base_url}{endpoint}"
        kwargs.setdefault('verify', self.verify_ssl)

        try:
            response = self.session.request(method, url, **kwargs)

            # Handle different status codes
            if response.status_code == 404:
                raise NotFoundError("Resource not found", status_code=404, response=response)
            elif response.status_code == 401:
                raise AuthenticationError("Authentication required or session expired")
            elif not response.ok:
                raise APIError(
                    f"API request failed: {response.status_code}",
                    status_code=response.status_code,
                    response=response
                )

            # Try to parse JSON response
            try:
                return response.json()
            except ValueError:
                return {"success": True, "data": response.text}

        except requests.RequestException as e:
            raise APIError(f"Request failed: {str(e)}")

    def login(self) -> bool:
        """
        Authenticate with the 3x-ui panel

        Returns:
            True if authentication successful

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            response = self._make_request(
                'POST',
                '/login',
                data={
                    'username': self.username,
                    'password': self.password
                }
            )

            if response.get('success'):
                self._authenticated = True
                return True
            else:
                raise AuthenticationError("Login failed: Invalid credentials")

        except APIError as e:
            raise AuthenticationError(f"Login failed: {str(e)}")

    def _ensure_authenticated(self):
        """Ensure the client is authenticated, login if needed"""
        if not self._authenticated:
            self.login()

    # ========== Inbound Management ==========

    def get_inbounds(self) -> List[Dict[str, Any]]:
        """
        Get list of all inbounds

        Returns:
            List of inbound configurations
        """
        self._ensure_authenticated()
        response = self._make_request('GET', '/panel/api/inbounds/list')
        return response.get('obj') or []

    def get_inbound(self, inbound_id: int) -> Dict[str, Any]:
        """
        Get specific inbound by ID

        Args:
            inbound_id: ID of the inbound

        Returns:
            Inbound configuration
        """
        self._ensure_authenticated()
        response = self._make_request('GET', f'/panel/api/inbounds/get/{inbound_id}')
        return response.get('obj', {})

    def add_inbound(self, config: Dict[str, Any]) -> bool:
        """
        Add a new inbound

        Args:
            config: Inbound configuration dictionary

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', '/panel/api/inbounds/add', json=config)
        return response.get('success', False)

    def delete_inbound(self, inbound_id: int) -> bool:
        """
        Delete an inbound

        Args:
            inbound_id: ID of the inbound to delete

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/inbounds/del/{inbound_id}')
        return response.get('success', False)

    def get_online_clients(self) -> List[str]:
        """
        Get list of currently online clients

        Returns:
            List of online client emails
        """
        self._ensure_authenticated()
        response = self._make_request('POST', '/panel/api/inbounds/onlines')
        return response.get('obj') or []

    # ========== Client Management ==========

    def add_client(self, client_config: Dict[str, Any]) -> bool:
        """
        Add a client to an inbound

        Args:
            client_config: Client configuration dictionary

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', '/panel/api/inbounds/addClient', json=client_config)
        return response.get('success', False)

    def update_client(self, client_id: str, config: Dict[str, Any]) -> bool:
        """
        Update client settings

        Args:
            client_id: Client UUID
            config: Updated client configuration

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/inbounds/updateClient/{client_id}', json=config)
        return response.get('success', False)

    def delete_client(self, inbound_id: int, email: str) -> bool:
        """
        Delete a client by email

        Args:
            inbound_id: Inbound ID
            email: Client email

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/inbounds/{inbound_id}/delClientByEmail/{email}')
        return response.get('success', False)

    def reset_client_traffic(self, email: str) -> bool:
        """
        Reset client traffic statistics

        Args:
            email: Client email

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/inbounds/resetClientTraffic/{email}')
        return response.get('success', False)

    # ========== Server Management ==========

    def get_server_status(self) -> Dict[str, Any]:
        """
        Get server status information

        Returns:
            Server status data
        """
        self._ensure_authenticated()
        response = self._make_request('GET', '/panel/api/server/status')
        return response.get('obj', {})

    def get_xray_version(self) -> List[str]:
        """
        Get available Xray versions

        Returns:
            List of available versions
        """
        self._ensure_authenticated()
        response = self._make_request('GET', '/panel/api/server/getXrayVersion')
        return response.get('obj') or []

    def restart_xray_service(self) -> bool:
        """
        Restart Xray service

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', '/panel/api/server/restartXrayService')
        return response.get('success', False)

    def install_xray(self, version: str) -> bool:
        """
        Install specific Xray version

        Args:
            version: Version to install

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/server/installXray/{version}')
        return response.get('success', False)

    def update_geofiles(self) -> bool:
        """
        Update geographic database files

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('POST', '/panel/api/server/updateGeofile')
        return response.get('success', False)

    def get_xray_logs(self, count: int = 100) -> str:
        """
        Get Xray service logs

        Args:
            count: Number of log lines to retrieve

        Returns:
            Log content as string
        """
        self._ensure_authenticated()
        response = self._make_request('POST', f'/panel/api/server/xraylogs/{count}')
        return response.get('obj', '')

    # ========== Backup ==========

    def backup_to_telegram(self) -> bool:
        """
        Backup configuration to Telegram bot

        Returns:
            True if successful
        """
        self._ensure_authenticated()
        response = self._make_request('GET', '/panel/api/backuptotgbot')
        return response.get('success', False)
