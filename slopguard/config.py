import json
import os
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field


class SlopGuardConfig(BaseModel):
    warn_threshold: float = Field(default=40.0, description="Risk score threshold (0-100) to emit warnings")
    block_threshold: float = Field(default=70.0, description="Risk score threshold (0-100) to block installation")
    allowlist: List[str] = Field(default_factory=list, description="List of package names explicitly allowed")
    enabled_registries: List[str] = Field(default_factory=lambda: ["npm", "pypi"], description="Registries to monitor")
    intel_sync_enabled: bool = Field(default=True, description="Enable malicious feed syncing")
    feed_cache_ttl_hours: int = Field(default=24, description="Cache TTL in hours for threat intel feed")
    interceptor_mode: str = Field(default="prompt", description="Action mode: prompt, block, or warn")


def get_global_config_path() -> Path:
    return Path.home() / ".slopguard" / "config.json"


def get_project_config_path(cwd: Optional[str] = None) -> Path:
    base = Path(cwd) if cwd else Path.cwd()
    return base / ".slopguard.json"


def load_config(cwd: Optional[str] = None) -> SlopGuardConfig:
    config_dict = {}

    # 1. Global config
    global_path = get_global_config_path()
    if global_path.exists():
        try:
            with open(global_path, "r", encoding="utf-8") as f:
                config_dict.update(json.load(f))
        except Exception:
            pass

    # 2. Project config (overrides global)
    project_path = get_project_config_path(cwd)
    if project_path.exists():
        try:
            with open(project_path, "r", encoding="utf-8") as f:
                project_data = json.load(f)
                config_dict.update(project_data)
        except Exception:
            pass

    return SlopGuardConfig(**config_dict)
