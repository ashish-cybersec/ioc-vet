"""Loads API keys from (in priority order): environment variables, then
~/.config/iocvet/config.toml. Environment variables always win, which
matters for CI use where you don't want a config file at all.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("IOCVET_CONFIG_DIR", Path.home() / ".config" / "iocvet"))
CONFIG_PATH = CONFIG_DIR / "config.toml"

_EXAMPLE_CONFIG = """\
# iocvet config — only needed for providers that require an API key.
# Free tiers: AbuseIPDB (1000 checks/day), URLhaus Auth-Key (free signup).
[keys]
abuseipdb = ""
urlhaus = ""
"""


def _load_toml_keys() -> dict[str, str]:
    if not CONFIG_PATH.exists():
        return {}
    with CONFIG_PATH.open("rb") as f:
        data = tomllib.load(f)
    return {k: v for k, v in data.get("keys", {}).items() if v}


def get_api_key(env_var: str, toml_key: str) -> str | None:
    """Look up one provider's key: env var first, then config file."""
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value
    return _load_toml_keys().get(toml_key) or None


def ensure_config_scaffold() -> Path:
    """Create an empty, commented config file on first run so users have
    something to edit instead of guessing the schema. Idempotent.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(_EXAMPLE_CONFIG)
    return CONFIG_PATH
