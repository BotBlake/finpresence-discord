import urllib.parse
import requests
import hashlib
import api_objects
import websockets
import ssl
import json
import time


class Config:
    def __init__(self, server_url: str, client: str, version: str, device: str):
        self.server_url = server_url.rstrip("/")
        self.client = client
        self.version = version
        self.device = device
        self.deviceid = self.generate_deviceid()
        self.ws_url = self.create_ws_url()

    def create_ws_url(self) -> str:
        parsed = urllib.parse.urlparse(self.server_url)
        if parsed.scheme == "https":
            ws_scheme = "wss"
        elif parsed.scheme == "http":
            ws_scheme = "ws"
        else:
            raise ValueError(f"Unsupported scheme: {parsed.scheme}")

        path = parsed.path.rstrip("/") + "/websocket"
        ws_url = urllib.parse.urlunparse((ws_scheme, parsed.netloc, path, "", "", ""))
        return ws_url

    def generate_deviceid(self, variable: str | None = "default") -> str:
        username_hash = hashlib.sha256(variable.encode("utf-8")).hexdigest()[:8]
        return f"{self.client}-{self.device}-{username_hash}"

    def update_deviceid(self, variable: str) -> None:
        self.deviceid = self.generate_deviceid(variable=variable)


# Public Jellyfin Endpoints
class Public:
    def __init__(self, sdk):
        self.sdk = sdk

    def get_users(self):
        url = urllib.parse.urljoin(self.sdk.config.server_url, "/Users/Public")
        response = requests.get(url)
        if not response.ok:
            raise Exception(f"ERROR: Server returned {response.status_code}")
        return [api_objects.User(user) for user in response.json()]


# Authenticate to Jellyfin Server
class Auth:
    def __init__(self, sdk):
        self.sdk = sdk
        self.quick_connect = self.QuickConnect(self)

    def header(self, token: str | None = None) -> str:
        """
        Build a properly encoded Jellyfin Authorization header.

        The header will follow the format:
          MediaBrowser Token="value", Client="value", Version="value", Device="value", DeviceId="value"

        All values are URL encoded.
        """
        params = {}
        if token is not None:
            params["Token"] = token

        params["Client"] = self.sdk.config.client
        params["Version"] = self.sdk.config.version
        params["Device"] = self.sdk.config.device
        params["DeviceId"] = self.sdk.config.deviceid

        header_parts = []
        for key, value in params.items():
            # URL encode each value (all characters that need encoding will be encoded)
            encoded_value = urllib.parse.quote(str(value), safe="")
            header_parts.append(f'{key}="{encoded_value}"')
        auth_header = "MediaBrowser " + ", ".join(header_parts)
        return auth_header

    def login_user(self, username, password):
        """
        Authenticate to the Jellyfin server using username and password.

        Sends a POST request to /Users/AuthenticateByName with a JSON payload.
        On success, extracts the access token and builds the final auth header.
        Returns a tuple: (final authorization header string, full response JSON)
        """
        url = urllib.parse.urljoin(
            self.sdk.config.server_url, "/Users/AuthenticateByName"
        )
        self.sdk.config.update_deviceid(username)

        # Build the initial header without token, including client information.
        headers = {"Authorization": self.header()}

        payload = {"Username": username, "Pw": password}
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        logged_in_user = api_objects.User(data.get("User"))
        # Expect the returned JSON to contain an access token under "AccessToken".
        token = data.get("AccessToken")
        if not token:
            raise ValueError("Authentication response did not contain an access token.")

        return token, logged_in_user

    def login_api_key(self, api_key: str) -> str:
        """
        Authenticate by building the authorization header using an API key.

        If no deviceid is provided, one is generated from the device name and a hashed username.
        """
        self.sdk.config.update_deviceid("apikey")
        return api_key

    class QuickConnect:
        def __init__(self, auth):
            self.auth = auth
            self.sdk = auth.sdk
            self.secret = None

        def initiate(self) -> str:
            url = urllib.parse.urljoin(
                self.sdk.config.server_url, "/QuickConnect/Initiate"
            )
            headers = {"Authorization": self.auth.header()}
            response = requests.post(url, headers=headers)
            if not response.ok:
                print("QuickConnect Error")
                exit()
            data = response.json()
            self.secret = data.get("Secret", "")
            return data.get("Code", "")

        def refresh_state(self):
            url = urllib.parse.urljoin(
                self.sdk.config.server_url,
                f"/QuickConnect/Connect?secret={self.secret}",
            )
            response = requests.get(url)
            data = response.json()
            authorized = bool(data.get("Authenticated", False))
            return authorized

        def auto_refresh_state(self):
            authenticated = False
            while not authenticated:
                authenticated = self.refresh_state()
                time.sleep(5)
            return self.secret

        def login(self):
            url = urllib.parse.urljoin(
                self.sdk.config.server_url, "/Users/AuthenticateWithQuickConnect"
            )

            # Build the initial header without a user specific deviceid
            headers = {"Authorization": self.auth.header()}
            payload = {"Secret": self.secret}
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            logged_in_user = api_objects.User(data.get("User"))

            # Set the deviceid to be user specific
            self.sdk.config.update_deviceid(logged_in_user.name)

            # Log-In again to get new User-Bound Access Token
            headers = {"Authorization": self.auth.header()}
            payload = {"Secret": self.secret}
            response = requests.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            logged_in_user = api_objects.User(data.get("User"))

            token = data.get("AccessToken")
            if not token:
                raise ValueError(
                    "Authentication response did not contain an access token."
                )

            return token, logged_in_user


# Features of the API
class SDK:
    def __init__(self, server_url: str, client: str, version: str, device: str):
        self.config = Config(server_url, client, version, device)
        self.auth = Auth(self)
        self.public = Public(self)
        self.user = self.User(self)
        self.websocket = self.Websocket(self)

    class User:
        def __init__(self, sdk):
            self.sdk = sdk
        def get(self, access_token):
            url = urllib.parse.urljoin(self.sdk.config.server_url, "/Users")
            headers = {"Authorization": self.sdk.auth.header(token=access_token)}
            response = requests.get(url, headers=headers)
            return [api_objects.User(user) for user in response.json()]

    class Websocket:
        def __init__(self, sdk):
            self.sdk = sdk
            self.subscriptions = []
        def announce_subscriptions(self, subscribtion_events):
            subscribtion_messages = []
            for subscription in subscribtion_events:
                subscribe_message = {
                    "MessageType": subscription,
                    "Data": "0,1000",  # 0ms initial delay, updates every 1000ms
                }
                subscribtion_messages.append(subscribe_message)
            self.subscribtions = subscribtion_messages
        async def open(self, access_token: str):
            """
            Open a websocket connection to the Jellyfin server, subscribe to events,
            and print received messages.
            """
            ws_url = self.sdk.config.ws_url

            print("Connecting to WebSocket URL:", ws_url)

            # Setup SSL context if needed (for wss:// connections)
            ssl_context = None
            if ws_url.startswith("wss://"):
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # Extra headers as a list of tuples (websockets accepts dicts as well)
            extra_headers = [
                ("Authorization", self.sdk.auth.header(token=access_token)),
                ("User-Agent", f"{self.sdk.config.client}/{self.sdk.config.version}"),
            ]

            try:
                async with websockets.connect(
                    ws_url, additional_headers=extra_headers, ssl=ssl_context
                ) as ws:
                    print("WebSocket connection established!")
                    
                    for subscribe_message in self.subscribtions:
                        await ws.send(json.dumps(subscribe_message))

                    # Listen for incoming messages indefinitely.
                    while True:
                        try:
                            message = await ws.recv()
                            if message is None:
                                break
                            print("Received:", message)
                        except websockets.ConnectionClosed:
                            print("WebSocket connection closed.")
                            break
            except Exception as e:
                print("Error with WebSocket connection:", e)
