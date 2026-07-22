"""Application configuration loaded from environment / .env."""
from __future__ import annotations

import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parent.parent
AUTH_TOKEN_FILE = BACKEND_DIR / ".lighthouse_auth_token"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LIGHTHOUSE_", env_file=".env", extra="ignore")

    auth_token: str = "change-me-please"
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    db_path: str = "lighthouse.db"
    nmap_xml_dir: str = "nmap_xml"
    # When True, the auth middleware is skipped (handy for first-run on localhost).
    auth_disabled: bool = False
    # When True, enqueue a host-discovery scan on process start (also runs every 5m).
    # Local .env often sets this false so uvicorn --reload does not kick off nmap each save.
    discovery_on_startup: bool = True

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


def _resolve_auth_token() -> str:
    """Reuse a persisted auto-token across reloads; mint one only when missing."""
    if AUTH_TOKEN_FILE.is_file():
        stored = AUTH_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if stored:
            return stored
    token = f"auto-{secrets.token_urlsafe(24)}"
    AUTH_TOKEN_FILE.write_text(token + "\n", encoding="utf-8")
    return token


settings = Settings()

# If the user left the default token and didn't explicitly disable auth, use a
# persisted auto-… value so uvicorn --reload does not rotate the UI bearer token.
if settings.auth_token == "change-me-please" and not settings.auth_disabled:
    settings.auth_token = _resolve_auth_token()
