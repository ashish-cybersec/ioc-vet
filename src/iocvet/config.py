"""Loads API keys from (in priority order): environment variables, then
~/.config/iocvet/config.toml. Environment variables always win, which
matters for CI use where you don't want a config file at all.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# tomllib landed in the stdlib in 3.11, but we support 3.10 — fall back to
# the `tomli` backport (same API) so `pip install` on 3.10 isn't broken.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 CI only
    import tomli as tomllib

CONFIG_DIR = Path(os.environ.get("IOCVET_CONFIG_DIR", Path.home() / ".config" / "iocvet"))
CONFIG_PATH = CONFIG_DIR / "config.toml"

_EXAMPLE_CONFIG = """\
# iocvet config — only needed for providers that require an API key.
# Free tiers: AbuseIPDB (1000 checks/day), URLhaus Auth-Key (free signup).
[keys]
abuseipdb = ""
urlhaus = ""
"""


class ConfigError(Exception):
    """Raised when the user's config file exists but can't be used.

    Separate from a missing file, which is normal and silent: this means the
    user hand-edited config.toml (which `iocvet configure` explicitly invites)
    and got something wrong. They deserve a sentence telling them what and
    where, not a traceback.
    """


def _load_toml_keys() -> dict[str, str]:
    if not CONFIG_PATH.exists():
        return {}
    if CONFIG_PATH.is_symlink():
        raise ConfigError(f"{CONFIG_PATH} is a symlink; refusing to read it.")
    try:
        with CONFIG_PATH.open("rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{CONFIG_PATH} is not valid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {CONFIG_PATH}: {exc}") from exc

    keys = data.get("keys", {})
    if not isinstance(keys, dict):
        raise ConfigError(f"{CONFIG_PATH}: [keys] must be a table, got {type(keys).__name__}")

    resolved: dict[str, str] = {}
    for name, value in keys.items():
        if not value:
            continue
        # A non-string here used to sail through: the truthiness check passed,
        # `iocvet providers` reported the provider as configured, and the bogus
        # value only blew up later inside httpx as a header-encoding error —
        # surfacing a config typo as a network fault.
        if not isinstance(value, str):
            raise ConfigError(
                f"{CONFIG_PATH}: [keys].{name} must be a string, got {type(value).__name__}"
            )
        resolved[name] = value
    return resolved


def get_api_key(env_var: str, toml_key: str) -> str | None:
    """Look up one provider's key: env var first, then config file."""
    env_value = os.environ.get(env_var)
    if env_value:
        return env_value
    return _load_toml_keys().get(toml_key) or None


def ensure_config_scaffold() -> Path:
    """Create an empty, commented config file on first run so users have
    something to edit instead of guessing the schema. Idempotent.

    The file is created 0600: it is expected to hold API keys, and a
    world-readable secrets file on a shared host is a real problem.
    """
    # `mode=` only applies when mkdir actually creates the directory, so an
    # existing dir keeps whatever permissions it had. chmod unconditionally.
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    CONFIG_DIR.chmod(0o700)
    # Refuse to touch a symlinked config: on a shared host a local attacker
    # could pre-plant config.toml as a symlink to a file they want chmod'd or
    # truncated, and our chmod/write would follow it to the target.
    if CONFIG_PATH.is_symlink():
        raise ConfigError(
            f"{CONFIG_PATH} is a symlink; refusing to operate on it. "
            "Remove it and re-run."
        )
    if not CONFIG_PATH.exists():
        CONFIG_PATH.touch(mode=0o600)
        CONFIG_PATH.write_text(_EXAMPLE_CONFIG)
    else:
        CONFIG_PATH.chmod(0o600)
    return CONFIG_PATH
