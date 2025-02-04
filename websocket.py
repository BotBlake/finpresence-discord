#!/usr/bin/env python3
import asyncio
import json
import ssl
import urllib.parse
import hashlib
import requests
import websockets

import api_objects
from util import Style, styled, get_input
# ------------------------------
# HTTP Authentication Functions
# ------------------------------


def build_auth_header(
    token=None, client=None, version=None, device=None, deviceid=None
):
    """
    Build a properly encoded Jellyfin Authorization header.

    The header will follow the format:
      MediaBrowser Token="value", Client="value", Version="value", Device="value", DeviceId="value"

    All values are URL encoded.
    """
    params = {}
    if token is not None:
        params["Token"] = token
    if client is not None:
        params["Client"] = client
    if version is not None:
        params["Version"] = version
    if device is not None:
        params["Device"] = device
    if deviceid is not None:
        params["DeviceId"] = deviceid

    header_parts = []
    for key, value in params.items():
        # URL encode each value (all characters that need encoding will be encoded)
        encoded_value = urllib.parse.quote(str(value), safe="")
        header_parts.append(f'{key}="{encoded_value}"')
    auth_header = "MediaBrowser " + ", ".join(header_parts)
    return auth_header


def get_public_users(base_url):
    """
    Get all public users from the Jellyfin server.
    """
    public_users = []
    url = urllib.parse.urljoin(base_url, "/Users/Public")
    response = requests.get(url)
    if not response.ok:
        print(f"ERROR: Server returned {response.status_code}")
        exit()
    user_response = response.json()
    for user in user_response:
        public_users.append(api_objects.User(user))
    return public_users


def login_user(base_url, username, password, client, version, device, deviceid=None):
    """
    Authenticate to the Jellyfin server using username and password.

    Sends a POST request to /Users/AuthenticateByName with a JSON payload.
    On success, extracts the access token and builds the final auth header.
    Returns a tuple: (final authorization header string, full response JSON)
    """
    url = urllib.parse.urljoin(base_url, "/Users/AuthenticateByName")

    # Generate a unique device id if one isn't provided.
    if deviceid is None:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        deviceid = f"{device}-{username_hash}"

    # Build the initial header without token, including client information.
    headers = {
        "Authorization": build_auth_header(
            client=client, version=version, device=device, deviceid=deviceid
        )
    }

    payload = {"Username": username, "Pw": password}
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    data = response.json()
    logged_in_user = api_objects.User(data.get("User"))
    # Expect the returned JSON to contain an access token under "AccessToken".
    token = data.get("AccessToken")
    if not token:
        raise ValueError("Authentication response did not contain an access token.")

    # Build the final authorization header including the token.
    final_auth_header = build_auth_header(
        token=token, client=client, version=version, device=device, deviceid=deviceid
    )
    return final_auth_header, logged_in_user


def login_via_api_key(api_key, client, version, device, username, deviceid=None):
    """
    Authenticate by building the authorization header using an API key.

    If no deviceid is provided, one is generated from the device name and a hashed username.
    """
    if deviceid is None:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        deviceid = f"{device}-{username_hash}"
    auth_header = build_auth_header(
        token=api_key, client=client, version=version, device=device, deviceid=deviceid
    )
    return auth_header


# ------------------------------
# WebSocket Functions (Async)
# ------------------------------


def create_ws_url(base_url: str) -> str:
    """
    Create the correct websocket URL from the base_url.

    Example:
      base_url = "http://localhost:8096"
    yields:
      ws://localhost:8096/websocket
    """
    parsed = urllib.parse.urlparse(base_url)
    # Determine the proper websocket scheme based on the HTTP scheme.
    if parsed.scheme == "https":
        ws_scheme = "wss"
    elif parsed.scheme == "http":
        ws_scheme = "ws"
    else:
        raise ValueError(f"Unsupported scheme: {parsed.scheme}")

    # Ensure the path is constructed correctly.
    path = parsed.path.rstrip("/") + "/websocket"
    ws_url = urllib.parse.urlunparse((ws_scheme, parsed.netloc, path, "", "", ""))
    return ws_url


async def open_websocket_connection(base_url: str, auth_header: str):
    """
    Open a websocket connection to the Jellyfin server, subscribe to events,
    and print received messages.
    """
    ws_url = create_ws_url(base_url)
    print("Connecting to WebSocket URL:", ws_url)

    # Setup SSL context if needed (for wss:// connections)
    ssl_context = None
    if ws_url.startswith("wss://"):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    # Extra headers as a list of tuples (websockets accepts dicts as well)
    extra_headers = [
        ("Authorization", auth_header),
        ("User-Agent", "Jellyfin-Python-Client/1.0"),
    ]

    try:
        async with websockets.connect(
            ws_url, additional_headers=extra_headers, ssl=ssl_context
        ) as ws:
            print("WebSocket connection established!")

            # Subscribe to an event (e.g. SessionsStart)
            subscribe_message = {
                "MessageType": "SessionsStart",
                "Data": "0,1000",  # 0ms initial delay, updates every 1000ms
            }
            await ws.send(json.dumps(subscribe_message))
            print("Subscribed to Sessions events.")

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


# ------------------------------
# Main Function
# ------------------------------


def main():
    # --- Configuration ---
    server_url = input("Enter your Server URL: ")
    client = "BlakeFlix"
    version = "1.0"
    device = "CLI Service"
    print()

    # --- 1. Build Login Menu ---
    valid_inputs = ["-2", "-1"]
    print("Authenticate via:")
    print("[-2] " + styled("API-Key", [Style.BOLD]))
    print("[-1] " + styled("Manual Login", [Style.BOLD]))
    public_users = get_public_users(server_url)

    if len(public_users) > 0:
        print("Or Log-In as:")
        for i, user in enumerate(public_users):
            valid_inputs.append(str(i))
            print(f"[{i}] {user.name}")
    print()
    selection = get_input(
        message="Please Select", default="-2", valid_inputs=valid_inputs
    )

    auth_header = None
    user = None

    # --- Auth via API-Token
    if selection == "-2":
        api_key = input("APIKEY: ")
        username = "apikey_login"  # Username for deviceid
        auth_header = login_via_api_key(api_key, client, version, device, username)
        print("\nAuthenticated using API key:")
        print("Authorization Header:")
        print(auth_header)

        # ToDo: Select User/s to track Activity

    # --- Manual Login
    if selection == "-1":
        username = input("Username: ")
        password = input("Password: ")
        auth_header, user = login_user(
            server_url, username, password, client, version, device
        )
        print("\nAuthenticated using username/password:")
        print("Final Authorization Header:")
        print(auth_header)
        print("Authentication Response:")
        print(f'Logged in as "{user.name}"')

    # --- User Login
    else:
        user = public_users[int(selection)]
        username = user.name
        # ToDo: Get QuickConnect here
        password = input(f"Password for {user.name}: ")
        auth_header, user = login_user(
            server_url, username, password, client, version, device
        )
        print("\nAuthenticated using username/password:")
        print("Final Authorization Header:")
        print(auth_header)
        print("Authentication Response:")
        print(f'Logged in as "{user.name}"')

    # --- 4. Open a WebSocket connection and wait for events ---
    # Since websockets uses asyncio, we need to run our async function.
    print()
    print("Starting Websocket Service...")
    asyncio.run(open_websocket_connection(server_url, auth_header))


if __name__ == "__main__":
    main()
