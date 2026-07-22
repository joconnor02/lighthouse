"""Application configuration loaded from environment / .env."""
from __future__ import annotations

import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LIGHTHOUSE_", env_file=".env", extra="ignore")

    auth_token: str = "change-me-please"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    db_path: str = "lighthouse.db"
    nmap_xml_dir: str = "nmap_xml"
    # When True, the auth middleware is skipped (handy for first-run on localhost).
    auth_disabled: bool = False

    @property
    def db_url(self) -> str:
        path = Path(self.db_path)
        if not path.is_absolute():
            path = BACKEND_DIR / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path}"

    @property
    def xml_dir(self) -> Path:
        p = Path(self.nmap_xml_dir)
        if not p.is_absolute():
            p = BACKEND_DIR / p
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()

# If the user left the default token and didn't explicitly disable auth, generate
# an ephemeral one and print a warning at startup so they can find it in logs.
if settings.auth_token == "change-me-please" and not settings.auth_disabled:
    settings.auth_token = f"auto-{secrets.token_urlsafe(24)}"
