import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

_DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


def load_config(path: str = None) -> dict:
    config_path = Path(path) if path else _DEFAULT_CONFIG_PATH
    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Environment variable overrides
    if os.getenv("SIEM_LOG_LEVEL"):
        config["siem"]["log_level"] = os.getenv("SIEM_LOG_LEVEL")
    if os.getenv("SIEM_DB_PATH"):
        config["storage"]["db_path"] = os.getenv("SIEM_DB_PATH")
    if os.getenv("SIEM_DASHBOARD_PORT"):
        config["dashboard"]["port"] = int(os.getenv("SIEM_DASHBOARD_PORT"))

    return config
