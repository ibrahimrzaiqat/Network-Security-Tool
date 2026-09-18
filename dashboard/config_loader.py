import sys
import os

_CONFIG_CACHE = None


def app_dir() -> str:
    """
    Folder where user-editable/persistent files live: config.env, and the
    scan_report_*.json files this app writes.

    - Normal `python app.py`: same folder as this script.
    - Frozen .exe (PyInstaller): the folder containing the .exe itself, NOT
      the temp extraction folder PyInstaller unpacks bundled files into
      (that folder is wiped after the program exits, which would silently
      delete every report between runs if we used it here).
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_dir() -> str:
    """
    Folder where bundled READ-ONLY assets live: templates/, static/.

    - Normal `python app.py`: same as app_dir().
    - Frozen .exe: PyInstaller's temp extraction folder (sys._MEIPASS) —
      this is fine here because these are files WE shipped, not files the
      user creates or that need to persist across runs.
    """
    if getattr(sys, "frozen", False):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def load_config() -> dict:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    config_path = os.path.join(app_dir(), "config.env")
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"config.env not found next to the app at:\n{config_path}\n"
            "Create it with:\nNVD_API_KEY=your_key_here\nGEMINI_API_KEY=your_key_here"
        )

    config = {}
    with open(config_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            config[key.strip()] = value.strip()

    _CONFIG_CACHE = config
    return config


def get_key(name: str) -> str:
    """Fetch one required key, with a clear error naming exactly what's missing."""
    config = load_config()
    value = config.get(name)
    if not value:
        raise KeyError(
            f"'{name}' is missing (or empty) in config.env. "
            f"Add a line like:\n{name}=your_key_here"
        )
    return value
