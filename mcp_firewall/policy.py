"""Loads policy.yaml and evaluates ALLOW/DENY for outgoing tools/call
requests, using labels resolved from the shared LabelStore.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_firewall.labels import Label, LabelStore

DEFAULT_THRESHOLD = 0.6
DEFAULT_NEAR_MISS_FLOOR = 0.15


@dataclass
class Verdict:
    allow: bool
    reason: str | None = None
    matched_labels: list[Label] = field(default_factory=list)

    @property
    def verdict_str(self) -> str:
        return "ALLOW" if self.allow else "DENY"


class Policy:
    def __init__(self, config: dict[str, Any]) -> None:
        self.sinks: set[tuple[str, str]] = set()
        for sink in config.get("sinks", []) or []:
            server = sink["server"]
            for tool in sink.get("tools", []) or []:
                self.sinks.add((server, tool))

        self.rules: list[str] = []
        self.allow_paths: list[str] = []
        for rule in config.get("rules", []) or []:
            if isinstance(rule, dict) and "deny" in rule:
                self.rules.append(rule["deny"])
            elif isinstance(rule, dict) and "allow_paths" in rule:
                self.allow_paths.extend(rule["allow_paths"] or [])

        matching_cfg = config.get("matching", {}) or {}
        self.threshold = float(matching_cfg.get("threshold", DEFAULT_THRESHOLD))
        self.near_miss_floor = float(matching_cfg.get("near_miss_floor", DEFAULT_NEAR_MISS_FLOOR))

        self.secret_patterns: list[str] = list(config.get("secret_patterns") or [])

        detectors_cfg = config.get("detectors", {}) or {}
        self.tool_poisoning_warn_threshold = float(detectors_cfg.get("warn_threshold", 0.5))

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(data)

    def is_sink(self, server: str, tool: str) -> bool:
        return (server, tool) in self.sinks

    def evaluate(
        self,
        *,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        label_store: LabelStore,
        repo_root: Path,
    ) -> Verdict:
        for key, value in arguments.items():
            if isinstance(value, str) and "path" in key.lower() and self.allow_paths:
                if not self._path_allowed(value):
                    return Verdict(False, f"argument '{key}' ({value!r}) is outside the allowed paths")

        if not self.is_sink(server, tool):
            return Verdict(True)

        matched: list[Label] = []
        for key, value in arguments.items():
            if not isinstance(value, str) or not value.strip():
                continue
            for m in label_store.find_matches(
                value,
                threshold=self.threshold,
                near_miss_floor=self.near_miss_floor,
                sink_server=server,
                sink_tool=tool,
                argument_name=key,
            ):
                matched.append(m.label)
                via = f" via {m.encoding}-encoded derivation" if m.encoding else ""
                if "secret_to_sink" in self.rules and m.label.is_secret:
                    return Verdict(
                        False,
                        f"argument '{key}' contains data labelled secret from {m.label.source_server} "
                        f"(match score {m.score:.2f}{via})",
                        matched,
                    )
                if "untrusted_to_sink_arg" in self.rules and m.label.trust_level == "untrusted":
                    return Verdict(
                        False,
                        f"argument '{key}' derived from untrusted source {m.label.source_server} "
                        f"(match score {m.score:.2f}{via})",
                        matched,
                    )

        return Verdict(True, matched_labels=matched)

    def _path_allowed(self, value: str) -> bool:
        normalized = value.replace("\\", "/")
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in self.allow_paths)
