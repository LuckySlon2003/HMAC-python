"""Module with config utils"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Tuple

from src.constants import DIGEST_MAP, HEX_RE, LOG_LEVELS
from src.exceptions import ConfigError
from src.models import Config


def _parse_listen(value: Any) -> Tuple[str, int]:
    if not isinstance(value, str) or ':' not in value:
        raise ConfigError('listen must be a string in format "host:port"')

    host, port_s = value.rsplit(':', 1)
    host = host.strip()
    port_s = port_s.strip()

    if not host:
        raise ConfigError('listen host must be non-empty')

    try:
        port = int(port_s, 10)
    except ValueError as e:
        raise ConfigError('listen port must be an integer') from e

    if not (1 <= port <= 65535):
        raise ConfigError('listen port must be between 1 and 65535')

    return host, port


def _decode_secret(secret_str: str) -> bytes:
    """Decode a hex-encoded secret string into raw bytes."""
    if not isinstance(secret_str, str) or not secret_str.strip():
        raise ConfigError("secret must be a non-empty string")

    s = secret_str.strip()

    if len(s) % 2 != 0:
        raise ConfigError("secret hex length must be even")

    if not HEX_RE.fullmatch(s):
        raise ConfigError(
            "secret must contain only hex characters [0-9a-fA-F]")

    try:
        raw = bytes.fromhex(s)
    except ValueError as e:
        raise ConfigError("secret hex is invalid") from e

    if not raw:
        raise ConfigError("secret decoded to empty bytes")

    return raw


def _require(d: dict[str, Any], key: str) -> Any:
    if key not in d:
        raise ConfigError(f'missing required config field: {key}')
    return d[key]


@lru_cache(maxsize=1)
def load_config(path: str | os.PathLike[str]) -> Config:
    """
    Load, validate, and normalize application configuration from a JSON file.

    Args:
        path: Path to the JSON configuration file. Can be a string or a
            Path-like object.

    Returns:
        A validated and normalized Config instance.

    Raises:
        FileNotFoundError: If the configuration file does not exist.
        json.JSONDecodeError: If the file content is not valid JSON.
        ConfigError: If the configuration structure or any field is invalid.
    """
    p = Path(path)
    data = json.loads(p.read_text(encoding='utf-8'))

    if not isinstance(data, dict):
        raise ConfigError('config root must be a JSON object')

    hmac_alg = _require(data, 'hmac_alg')
    if hmac_alg not in DIGEST_MAP.keys():
        raise ConfigError(f'hmac_alg must be one of {DIGEST_MAP.keys()}')

    log_level = _require(data, 'log_level')
    if log_level not in LOG_LEVELS:
        raise ConfigError(
            f'log_level must be one of: {LOG_LEVELS}')

    listen = _require(data, 'listen')
    host, port = _parse_listen(listen)

    max_msg_size_bytes = _require(data, 'max_msg_size_bytes')
    if not isinstance(max_msg_size_bytes, int):
        raise ConfigError('max_msg_size_bytes must be an integer')
    if max_msg_size_bytes <= 0:
        raise ConfigError('max_msg_size_bytes must be > 0')

    secret_str = _require(data, 'secret')
    secret_bytes = _decode_secret(secret_str)

    return Config(
        hmac_alg=hmac_alg,
        secret=secret_bytes,
        log_level=log_level,
        listen_host=host,
        listen_port=port,
        max_msg_size_bytes=max_msg_size_bytes,
    )
