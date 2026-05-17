"""Regression tests for the packaged control-plane runtime entry point."""

from __future__ import annotations

from pathlib import Path

from api.main import app as canonical_app
from main import app as compatibility_app


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_compatibility_main_uses_canonical_api_app():
    assert compatibility_app is canonical_app


def test_dockerfile_runs_canonical_api_app():
    dockerfile = REPO_ROOT / "control-plane" / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")

    assert '"api.main:app"' in text
    assert '"main:app"' not in text


def test_dockerfile_copies_runtime_policies():
    dockerfile = REPO_ROOT / "control-plane" / "Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")

    assert "COPY policies ./policies" in text
