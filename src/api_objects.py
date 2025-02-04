from typing import List, Dict, Optional


class User:
    def __init__(self, data: Dict):
        self.name: str = data.get("Name", "")
        self.server_id: str = data.get("ServerId", "")
        self.server_name: str = data.get("ServerName", "")
        self.id: str = data.get("Id", "")
        self.primary_image_tag: str = data.get("PrimaryImageTag", "")
        self.has_password: bool = data.get("HasPassword", False)
        self.has_configured_password: bool = data.get("HasConfiguredPassword", False)
        self.has_configured_easy_password: bool = data.get(
            "HasConfiguredEasyPassword", False
        )
        self.enable_auto_login: bool = data.get("EnableAutoLogin", False)
        self.last_login_date: str = data.get("LastLoginDate", "")
        self.last_activity_date: str = data.get("LastActivityDate", "")

        # Configuration
        self.configuration: Dict = data.get("Configuration", {})

        # Policy
        self.policy: Dict = data.get("Policy", {})

    def __repr__(self):
        return f"User(name={self.name}, id={self.id}, server={self.server_name})"
