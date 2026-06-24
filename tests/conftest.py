"""Shared pytest configuration and fixtures."""

from __future__ import annotations

import warnings

import pytest

from tip.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    """In-memory, zero-side-effect settings for tests."""
    return Settings(
        misp_api_key="test-key",
        otx_api_key="test-key",
        cache_backend="sqlite",
        cache_sqlite_path=":memory:",
        slack_webhook_url="",
    )


@pytest.fixture(autouse=True)
def _silence_third_party_deprecations():
    """Keep test output focused on our code, not dependency deprecations."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="pymisp.*")
        warnings.filterwarnings("ignore", category=DeprecationWarning, module="dateutil.*")
        yield
