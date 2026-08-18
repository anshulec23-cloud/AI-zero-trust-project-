"""
security.py - Centralized Security Module for Aegis ICS Desktop Application

Provides runtime security utilities including token-based request authentication,
ephemeral port allocation, path resolution for PyInstaller builds, cryptographic
secret generation, and basic anti-debug detection.
"""

import ctypes 
import functools 
import os 
import secrets 
import socket 
import sys 
from typing import Callable ,Any 

from flask import jsonify ,request 





APP_VERSION :str ="2.4.0"
"""Current application version string."""

GITHUB_REPO :str ="anshulec23-cloud/aegis-ics"
"""GitHub repository identifier used for update checks."""


DEFAULT_DEVICE_KEYS = {
    "ESP32_001": "aegis_shared_esp32_001_secret_key_v2",
    "ESP32_002": "aegis_shared_esp32_002_secret_key_v2",
    "ESP32_003": "aegis_shared_esp32_003_secret_key_v2",
    "ESP32_004": "aegis_shared_esp32_004_secret_key_v2",
    "ESP32_MAIN": "aegis_shared_esp32_001_secret_key_v2",
    "ESP32_SLAVE_01": "aegis_shared_esp32_slave_01_secret_key_v2",
    "ESP32_SLAVE_02": "aegis_shared_esp32_slave_02_secret_key_v2",
    "ESP32_SLAVE_03": "aegis_shared_esp32_slave_03_secret_key_v2",
    "ESP32_SLAVE_04": "aegis_shared_esp32_slave_04_secret_key_v2",
    "SLAVE_01": "aegis_shared_esp32_slave_01_secret_key_v2",
    "SLAVE_02": "aegis_shared_esp32_slave_02_secret_key_v2",
    "SLAVE_03": "aegis_shared_esp32_slave_03_secret_key_v2",
    "SLAVE_04": "aegis_shared_esp32_slave_04_secret_key_v2",
}

DEVICE_KEYS = DEFAULT_DEVICE_KEYS

def normalize_device_id(raw_id: Any) -> str:
    """Normalize various device identifier formats (e.g. SLAVE_01, 1, ESP32_SLAVE_01) to standard canonical IDs."""
    if not raw_id:
        return "ESP32_001"
    s = str(raw_id).strip()
    s_clean = s.upper().replace("-", "_").replace(" ", "_").strip()
    
    mapping = {
        "1": "ESP32_001", "01": "ESP32_001", "001": "ESP32_001",
        "NODE1": "ESP32_001", "NODE_1": "ESP32_001", "NODE_01": "ESP32_001", "NODE_001": "ESP32_001",
        "SLAVE1": "ESP32_001", "SLAVE_1": "ESP32_001", "SLAVE_01": "ESP32_001", "SLAVE_001": "ESP32_001",
        "ESP32_1": "ESP32_001", "ESP32_01": "ESP32_001", "ESP32_001": "ESP32_001",
        "ESP32_SLAVE_1": "ESP32_001", "ESP32_SLAVE_01": "ESP32_001", "ESP32_SLAVE_001": "ESP32_001",
        "ESP32_MAIN": "ESP32_001", "MAIN": "ESP32_001", "MASTER": "ESP32_001", "ESP32_MASTER": "ESP32_001",

        "2": "ESP32_002", "02": "ESP32_002", "002": "ESP32_002",
        "NODE2": "ESP32_002", "NODE_2": "ESP32_002", "NODE_02": "ESP32_002", "NODE_002": "ESP32_002",
        "SLAVE2": "ESP32_002", "SLAVE_2": "ESP32_002", "SLAVE_02": "ESP32_002", "SLAVE_002": "ESP32_002",
        "ESP32_2": "ESP32_002", "ESP32_02": "ESP32_002", "ESP32_002": "ESP32_002",
        "ESP32_SLAVE_2": "ESP32_002", "ESP32_SLAVE_02": "ESP32_002", "ESP32_SLAVE_002": "ESP32_002",

        "3": "ESP32_003", "03": "ESP32_003", "003": "ESP32_003",
        "NODE3": "ESP32_003", "NODE_3": "ESP32_003", "NODE_03": "ESP32_003", "NODE_003": "ESP32_003",
        "SLAVE3": "ESP32_003", "SLAVE_3": "ESP32_003", "SLAVE_03": "ESP32_003", "SLAVE_003": "ESP32_003",
        "ESP32_3": "ESP32_003", "ESP32_03": "ESP32_003", "ESP32_003": "ESP32_003",
        "ESP32_SLAVE_3": "ESP32_003", "ESP32_SLAVE_03": "ESP32_003", "ESP32_SLAVE_003": "ESP32_003",

        "4": "ESP32_004", "04": "ESP32_004", "004": "ESP32_004",
        "NODE4": "ESP32_004", "NODE_4": "ESP32_004", "NODE_04": "ESP32_004", "NODE_004": "ESP32_004",
        "SLAVE4": "ESP32_004", "SLAVE_4": "ESP32_004", "SLAVE_04": "ESP32_004", "SLAVE_004": "ESP32_004",
        "ESP32_4": "ESP32_004", "ESP32_04": "ESP32_004", "ESP32_004": "ESP32_004",
        "ESP32_SLAVE_4": "ESP32_004", "ESP32_SLAVE_04": "ESP32_004", "ESP32_SLAVE_004": "ESP32_004",
    }

    if s_clean in mapping:
        return mapping[s_clean]
    
    import re
    m = re.search(r'(\d+)$', s_clean)
    if m:
        val = int(m.group(1))
        if 1 <= val <= 4:
            return f"ESP32_{val:03d}"

    return s

def load_custom_device_keys() -> dict:
    """Load optional custom HMAC keys from a local device_keys.json configuration file if present."""
    import json
    search_paths = [
        "device_keys.json",
        os.path.join(os.path.dirname(__file__), "device_keys.json"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "device_keys.json"),
    ]
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        search_paths.insert(0, os.path.join(os.path.dirname(sys.executable), "device_keys.json"))

    for p in search_paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    keys = json.load(f)
                    if isinstance(keys, dict):
                        return keys
            except Exception as e:
                print(f"[Security] Warning: Failed to load {p}: {e}")
    return {}

def get_device_key(device_id: str = "ESP32_001") -> str:
    """Return a consistent device HMAC pre-shared key across processes, supporting env vars, device_keys.json, and defaults."""
    norm_id = normalize_device_id(device_id)
    # 1. Environment variable override
    env_key = os.environ.get(f"DEVICE_KEY_{norm_id}")
    if env_key:
        return env_key
    # 2. Config file override (device_keys.json)
    custom_keys = load_custom_device_keys()
    if custom_keys:
        if norm_id in custom_keys:
            return custom_keys[norm_id]
        if device_id in custom_keys:
            return custom_keys[device_id]
    # 3. Default built-in keys
    if norm_id in DEFAULT_DEVICE_KEYS:
        return DEFAULT_DEVICE_KEYS[norm_id]
    if device_id in DEFAULT_DEVICE_KEYS:
        return DEFAULT_DEVICE_KEYS[device_id]
    return f"aegis_shared_{norm_id.lower()}_secret_key_v2"






def find_free_port ()->int :
    """Find a random available ephemeral port on localhost.

    Binds a TCP socket to ``127.0.0.1:0`` and lets the operating system
    assign an available port, then immediately releases the socket.

    Returns:
        int: An available port number assigned by the OS.
    """
    with socket .socket (socket .AF_INET ,socket .SOCK_STREAM )as s :
        s .bind (("127.0.0.1",0 ))
        s .setsockopt (socket .SOL_SOCKET ,socket .SO_REUSEADDR ,1 )
        _ ,port =s .getsockname ()
        return port 






def resource_path (relative_path :str )->str :
    """Resolve a file path for both development and frozen PyInstaller builds.

    When the application is bundled with PyInstaller, files are extracted to a
    temporary directory referenced by ``sys._MEIPASS``. During normal
    development the base path is the directory containing this module.

    Args:
        relative_path: A path relative to the application root / bundle root.

    Returns:
        str: The absolute path to the requested resource.
    """

    base_path :str =getattr (sys ,"_MEIPASS",os .path .dirname (os .path .abspath (__file__ )))
    return os .path .join (base_path ,relative_path )






def require_webview_token (f :Callable [...,Any ])->Callable [...,Any ]:
    """Flask route decorator that validates the ``X-PYWEBVIEW-TOKEN`` header.

    The decorator enforces that every decorated request carries a valid
    pywebview token, preventing external processes from accessing the local
    Flask server.

    Behaviour:
    * If the ``AEGIS_DESKTOP_MODE`` environment variable is **not** set the
      check is skipped entirely.  This allows running the Flask backend in
      isolation during development or testing without requiring pywebview.
    * When ``AEGIS_DESKTOP_MODE`` **is** set, the ``webview`` module is
      imported lazily and the header value is compared against
      ``webview.token``.  A mismatch (or missing header) results in a
      ``403 Forbidden`` response.

    Returns:
        The decorated function with token validation applied.
    """

    @functools .wraps (f )
    def decorated_function (*args :Any ,**kwargs :Any )->Any :
        from flask import current_app
        if current_app and current_app.config.get("TESTING"):
            return f(*args, **kwargs)

        if not os .environ .get ("AEGIS_DESKTOP_MODE"):
            return f (*args ,**kwargs )

        from flask import session 
        if session .get ("user_id"):
            return f (*args ,**kwargs )

        try :
            import webview 
        except ImportError :

            return jsonify ({"error":"Forbidden – webview module unavailable"}),403 

        token :str |None =request .headers .get ("X-PYWEBVIEW-TOKEN")

        if not token or token !=webview .token :
            return jsonify ({"error":"Forbidden – invalid or missing token"}),403 

        return f (*args ,**kwargs )

    return decorated_function 






def generate_runtime_secret ()->str :
    """Generate a cryptographically secure runtime secret.

    Uses :func:`secrets.token_hex` to produce a 64-character hexadecimal
    string (256 bits of entropy), suitable for use as a Flask session secret
    key or similar purpose.

    Returns:
        str: A 64-character hex string.
    """
    return secrets .token_hex (32 )






def check_debugger ()->bool :
    """Perform basic anti-debug detection on Windows.

    Calls ``kernel32.IsDebuggerPresent()`` via :mod:`ctypes` to determine
    whether the current process is being run under a debugger.

    Returns:
        bool: ``True`` if a debugger is detected, ``False`` otherwise.
              Always returns ``False`` on non-Windows platforms or if the
              check fails for any reason.
    """
    try :
        return bool (ctypes .windll .kernel32 .IsDebuggerPresent ())
    except (AttributeError ,OSError ):

        return False 
