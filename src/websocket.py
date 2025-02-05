#!/usr/bin/env python3
import asyncio

from jellyfin_sdk import (
    get_public_users,
    login_api_key,
    login_user,
    open_websocket_connection,
)
from util import Style, styled, get_input


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
        auth_header = login_api_key(api_key, client, version, device, username)
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
