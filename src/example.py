import jellyfin_sdk


def main():
    server_url = "http://127.0.0.1:8096"
    jfsdk = jellyfin_sdk.SDK(
        server_url=server_url, client="BlakeFlix", version="dev", device="My Computer"
    )
    access_token, user = jfsdk.auth.login_user(
        username="CoolTestUser", password="Passwort"
    )
    print(f"Last Login {user.last_login_date}")


if __name__ == "__main__":
    main()
