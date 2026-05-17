"""Configuration for optional live Playwright tests."""

import os
from pathlib import Path

import pytest

PLAYWRIGHT_TEST_DIR = Path(__file__).parent.resolve()


def pytest_collection_modifyitems(config, items):
    """Keep live browser tests out of the default beta release test run."""
    enabled = os.getenv("RUN_PLAYWRIGHT_LIVE_TESTS", "").lower() in {"1", "true", "yes"}
    if enabled:
        return

    skip_live = pytest.mark.skip(
        reason="live Playwright tests require RUN_PLAYWRIGHT_LIVE_TESTS=1 and a running API stack"
    )
    for item in items:
        if PLAYWRIGHT_TEST_DIR in Path(item.path).resolve().parents:
            item.add_marker(skip_live)
