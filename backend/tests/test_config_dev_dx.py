"""Tests for config helpers used during local --reload iteration."""
from __future__ import annotations

from pathlib import Path

import pytest


def test_resolve_auth_token_persists_and_reuses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import app.config as config_mod

    token_file = tmp_path / ".lighthouse_auth_token"
    monkeypatch.setattr(config_mod, "AUTH_TOKEN_FILE", token_file)

    first = config_mod._resolve_auth_token()
    assert first.startswith("auto-")
    assert token_file.read_text(encoding="utf-8").strip() == first

    second = config_mod._resolve_auth_token()
    assert second == first


def test_discovery_on_startup_setting_defaults_true():
    from app.config import Settings

    assert Settings(auth_token="x").discovery_on_startup is True
    assert Settings(auth_token="x", discovery_on_startup=False).discovery_on_startup is False
