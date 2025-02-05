#!/usr/bin/env python3
import asyncio
import getpass
import jellyfin_sdk
from util import Style, styled, get_input


def main():
    # --- Configuration ---
    server_url = input("Enter your Server URL: ")
    client = "BlakeFlix"
    version = "1.0"
    device = "CLI Service"
    jellyfin = jellyfin_sdk.SDK(
        server_url=server_url, client=client, version=version, device=device
    )
    print()

    # --- 1. Build Login Menu ---
    valid_inputs = ["-3", "-2", "-1"]
    print("Authenticate via:")
    print("[-3] " + styled("API-Key", [Style.BOLD]))
    print("[-2] " + styled("Manual Login", [Style.BOLD]))
    print("[-1] " + styled("Quick Connect", [Style.BOLD]))
    public_users = jellyfin.public.get_users()

    if len(public_users) > 0:
        print("Or Log-In as:")
        for i, user in enumerate(public_users):
            valid_inputs.append(str(i))
            print(f"[{i}] {user.name}")
    print()
    selection = get_input(
        message="Please Select", default="-2", valid_inputs=valid_inputs
    )

    access_token = None
    user = None

    # --- Auth via API-Token
    if selection == "-3":
        api_key = getpass.getpass("APIKEY: ")
        access_token = jellyfin.auth.login_api_key(api_key=api_key)

        # ToDo: Select User/s to track Activity

    # --- Manual Login
    elif selection == "-2":
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        access_token, user = jellyfin.auth.login_user(
            username=username, password=password
        )
        print(f'Logged in as "{user.name}"')
        print(f"Last Login {user.last_login_date}")

    # --- Quick Connect
    elif selection == "-1":
        code = jellyfin.auth.quick_connect.initiate()
        print(f"Use QuickConnect Code [{code}]")
        jellyfin.auth.quick_connect.auto_refresh_state()
        access_token, user = jellyfin.auth.quick_connect.login()
        print(f'Logged in as "{user.name}"')
        print(f"Last Login {user.last_login_date}")

    # --- User Login
    else:
        user = public_users[int(selection)]
        username = user.name
        # ToDo: Get QuickConnect here
        password = getpass.getpass(f"Password for {user.name}: ")
        access_token, user = jellyfin.auth.login_user(
            username=username, password=password
        )
        print(f'Logged in as "{user.name}"')
        print(f"Last Login {user.last_login_date}")

    # --- 4. Open a WebSocket connection and wait for events ---
    # Since websockets uses asyncio, we need to run our async function.
    print()
    print("Starting Websocket Service...")
    asyncio.run(jellyfin.open_websocket_connection(access_token))


if __name__ == "__main__":
    main()
