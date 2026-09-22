import yaml
import os

DEFAULT_CONFIG_PATH = os.path.join("config", "settings.yaml")


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}