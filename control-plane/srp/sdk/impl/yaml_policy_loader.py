"""
yaml_policy_loader.py — YAML-backed policy loader for the SRP VerdictEngine.

Loads a PolicySet from a YAML file and optionally watches it for changes,
hot-reloading the policy without a restart.

YAML format mirrors the PolicySet / PolicyRule Pydantic models:

    name: my-policy
    version: "1.0.0"
    rules:
      - id: block-delete
        description: "Block delete operations"
        effect: BLOCK
        priority: 100
        condition:
          operations: [delete, drop]
      - id: allow-reads
        description: "Allow read operations"
        effect: ALLOW
        priority: 900
        condition:
          operations: [read, list, get]
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger("srp.yaml_policy_loader")


class YamlPolicyLoader:
    """
    Load and optionally hot-reload a YAML policy file into a PolicySet.

    Usage:
        loader = YamlPolicyLoader()
        loader.load("/path/to/policy.yaml")
        loader.watch("/path/to/policy.yaml", callback=lambda p: print("reloaded", p))

        policy_set = loader.policy_set   # None until load() is called
    """

    def __init__(self) -> None:
        self._policy_set = None
        self._path: str | None = None
        self._watcher_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    @property
    def policy_set(self):
        with self._lock:
            return self._policy_set

    def load(self, path: str) -> None:
        """Load (or reload) the policy from the given YAML file path."""
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML is not installed. Run: pip install PyYAML")
            return

        from srp.policy import PolicyCondition, PolicyEffect, PolicyRule, PolicySet

        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Policy file not found: %s", path)
            return

        try:
            with file_path.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:
            logger.error("Failed to parse policy YAML at %s: %s", path, exc)
            return

        if not isinstance(data, dict):
            logger.error("Policy YAML must be a mapping at the top level: %s", path)
            return

        try:
            rules = []
            for rule_data in data.get("rules", []):
                condition_data = rule_data.get("condition", {})
                condition = PolicyCondition(
                    tenants=condition_data.get("tenants"),
                    roles=condition_data.get("roles"),
                    environments=condition_data.get("environments"),
                    api_refs=condition_data.get("api_refs"),
                    operations=condition_data.get("operations"),
                    max_numeric_parameters=condition_data.get("max_numeric_parameters", {}),
                )
                rules.append(
                    PolicyRule(
                        id=rule_data["id"],
                        description=rule_data["description"],
                        effect=PolicyEffect(rule_data["effect"].upper()),
                        condition=condition,
                        priority=rule_data.get("priority", 1000),
                    )
                )

            policy_set = PolicySet(
                name=data["name"],
                version=str(data["version"]),
                rules=rules,
            )

            with self._lock:
                self._policy_set = policy_set
                self._path = path

            logger.info(
                "Policy loaded: name=%s version=%s rules=%d path=%s",
                policy_set.name,
                policy_set.version,
                len(rules),
                path,
            )
        except Exception as exc:
            logger.error("Failed to build PolicySet from %s: %s", path, exc)

    def watch(self, path: str, callback: Callable[[Path], None] | None = None) -> None:
        """
        Watch a YAML file for changes and reload on modification.

        Uses a polling thread (1-second interval) — no inotify dependency.
        Safe to call multiple times; only one watcher runs at a time.
        """
        if self._watcher_thread and self._watcher_thread.is_alive():
            return

        self._stop_event.clear()

        def _poll():
            file_path = Path(path)
            last_mtime: float | None = None
            while not self._stop_event.wait(timeout=1.0):
                try:
                    mtime = file_path.stat().st_mtime
                    if last_mtime is not None and mtime != last_mtime:
                        logger.info("Policy file changed, reloading: %s", path)
                        self.load(path)
                        if callback:
                            try:
                                callback(file_path)
                            except Exception as exc:
                                logger.warning("Policy reload callback failed: %s", exc)
                    last_mtime = mtime
                except FileNotFoundError:
                    pass
                except Exception as exc:
                    logger.warning("Policy watcher error: %s", exc)

        self._watcher_thread = threading.Thread(
            target=_poll, daemon=True, name="gavel-policy-watcher"
        )
        self._watcher_thread.start()
        logger.info("Policy file watcher started for %s", path)

    def stop_watching(self) -> None:
        """Stop the file watcher thread."""
        self._stop_event.set()
        if self._watcher_thread:
            self._watcher_thread.join(timeout=3.0)
            self._watcher_thread = None
        logger.info("Policy file watcher stopped")
