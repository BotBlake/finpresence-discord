#!/usr/bin/env python3
import requests
import urllib.parse
import hashlib


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
        # URL encode each value; safe='' means every character that needs encoding will be encoded.
        encoded_value = urllib.parse.quote(str(value), safe="")
        header_parts.append(f'{key}="{encoded_value}"')
    auth_header = "MediaBrowser " + ", ".join(header_parts)
    return auth_header


def get_public_users(base_url):
    """
    Get all public users from the Jellyfin server.
    """
    url = urllib.parse.urljoin(base_url, "/Users/Public")
    response = requests.get(url)
    response.raise_for_status()  # Raise an error if the request failed
    return response.json()


def login_user(base_url, username, password, client, version, device, deviceid=None):
    """
    Authenticate to the Jellyfin server using username and password.

    Sends a POST request to /Users/AuthenticateByName with a JSON payload.
    An initial Authorization header with client information is included.
    On success, extracts the access token and builds the final auth header.
    Returns a tuple: (final authorization header string, full response JSON)
    """
    url = urllib.parse.urljoin(base_url, "/Users/AuthenticateByName")

    # Generate a unique device id if one isn't provided.
    if deviceid is None:
        username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
        deviceid = f"{device}-{username_hash}"

    # Build the client header (without the token) to include client information in the request.
    headers = {
        "Authorization": build_auth_header(
            client=client, version=version, device=device, deviceid=deviceid
        )
    }

    payload = {"Username": username, "Pw": password}
    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Expect the returned JSON to contain an access token under "AccessToken".
        token = data.get("AccessToken")
        if not token:
            raise ValueError("Authentication response did not contain an access token.")

        # Build the final authorization header including the token.
        final_auth_header = build_auth_header(
            token=token,
            client=client,
            version=version,
            device=device,
            deviceid=deviceid,
        )
        return final_auth_header, data
    except requests.exceptions.RequestException as e:
        print(f"Authentication failed: {str(e)}")
        raise


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


def main():
    # --- Configuration ---
    base_url = "MyDomain"  # Replace with your Jellyfin server URL.
    client = "BlakeFlix_auth"
    version = "1.0"
    device = "CLI Service"

    # --- 1. Get all public users ---
    try:
        users = get_public_users(base_url)
        print("Public Users:")
        print(users)
    except Exception as e:
        print(f"Error fetching public users: {e}")

    # --- 2. Login as User (Password) ---
    username = "Username"  # Replace with a valid username
    password = "CoolPassword"  # Replace with the correct password for the user
    try:
        auth_header, auth_response = login_user(
            base_url, username, password, client, version, device
        )
        print("\nAuthenticated using username/password:")
        print("Final Authorization Header:")
        print(auth_header)
        print("Authentication Response:")
        print(auth_response)
    except Exception as e:
        print(f"Error logging in as user: {e}")

    # --- 3. Login Via API Key ---
    api_key = "APIKEY"  # Replace with your actual API key
    try:
        api_auth_header = login_via_api_key(api_key, client, version, device, username)
        print("\nAuthenticated using API key:")
        print("Authorization Header:")
        print(api_auth_header)
    except Exception as e:
        print(f"Error logging in via API key: {e}")


if __name__ == "__main__":
    main()
