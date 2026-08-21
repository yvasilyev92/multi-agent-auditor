"""Logging setup used by the Streamlit app and the eval CLI."""

from __future__ import annotations

import logging

from auditor.config import get_settings


def setup_logging() -> None:
    """Configure root logging once. Safe to call multiple times."""
    settings = get_settings()
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(settings.log_level)
        return
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
