"""iocvet — multi-source IOC enrichment from your terminal."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version recorded at install time from
    # pyproject.toml. Avoids the classic drift where __init__ says 0.1.0 while
    # pyproject (and the release tag) say 0.2.0, making --version lie.
    __version__ = version("ioc-vet")
except PackageNotFoundError:  # pragma: no cover - only when running from a raw checkout
    __version__ = "0.0.0+unknown"
