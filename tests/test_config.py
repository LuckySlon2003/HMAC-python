import json
from pathlib import Path

import pytest

from src.config import load_config
from src.exceptions import ConfigError


@pytest.fixture(autouse=True)
def _clear_config_cache() -> None:
    """
    Ensure load_config cache is cleared between tests.
    """
    load_config.cache_clear()


def _write_config(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _valid_config(secret_hex: str = "00" * 32) -> dict:
    return {
        "hmac_alg": "SHA256",
        "secret": secret_hex,
        "log_level": "info",
        "listen": "0.0.0.0:8080",
        "max_msg_size_bytes": 1048576,
    }


def test_load_config_ok(tmp_path: Path) -> None:
    path = _write_config(tmp_path, _valid_config(secret_hex="0a" * 32))

    cfg = load_config(path)

    assert cfg.hmac_alg == "SHA256"
    assert cfg.log_level == "info"
    assert cfg.listen_host == "0.0.0.0"
    assert cfg.listen_port == 8080
    assert cfg.max_msg_size_bytes == 1048576

    assert isinstance(cfg.secret, bytes)
    assert cfg.secret == bytes.fromhex("0a" * 32)
    assert len(cfg.secret) == 32


@pytest.mark.parametrize(
    "missing_key",
    ["hmac_alg", "secret", "log_level", "listen", "max_msg_size_bytes"],
)
def test_load_config_missing_required_field_raises(
    tmp_path: Path,
    missing_key: str
) -> None:
    data = _valid_config()
    data.pop(missing_key)
    path = _write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=r"missing required config field:"):
        load_config(path)


def test_load_config_root_not_object_raises(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")

    with pytest.raises(ConfigError, match="config root must be a JSON object"):
        load_config(p)


def test_load_config_invalid_hmac_alg_raises(tmp_path: Path) -> None:
    data = _valid_config()
    data["hmac_alg"] = "MD5"
    path = _write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=r"hmac_alg must be one of"):
        load_config(path)


def test_load_config_invalid_log_level_raises(tmp_path: Path) -> None:
    data = _valid_config()
    data["log_level"] = "verbose"
    path = _write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=r"log_level must be one of"):
        load_config(path)


@pytest.mark.parametrize(
    "listen_value, err_match",
    [
        (123, 'listen must be a string in format "host:port"'),
        ("noport", 'listen must be a string in format "host:port"'),
        (":8080", "listen host must be non-empty"),
        ("0.0.0.0:notint", "listen port must be an integer"),
        ("0.0.0.0:0", "listen port must be between 1 and 65535"),
        ("0.0.0.0:70000", "listen port must be between 1 and 65535"),
    ],
)
def test_load_config_invalid_listen_raises(
    tmp_path: Path, listen_value, err_match: str
) -> None:
    data = _valid_config()
    data["listen"] = listen_value
    path = _write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=err_match):
        load_config(path)


@pytest.mark.parametrize(
    "max_size, err_match",
    [
        ("100", "max_msg_size_bytes must be an integer"),
        (0, "max_msg_size_bytes must be > 0"),
        (-1, "max_msg_size_bytes must be > 0"),
    ],
)
def test_load_config_invalid_max_msg_size_raises(
    tmp_path: Path, max_size, err_match: str
) -> None:
    data = _valid_config()
    data["max_msg_size_bytes"] = max_size
    path = _write_config(tmp_path, data)

    with pytest.raises(ConfigError, match=err_match):
        load_config(path)


def test_load_config_cache_returns_same_instance(tmp_path: Path) -> None:
    path = _write_config(tmp_path, _valid_config(secret_hex="01" * 32))

    cfg1 = load_config(path)
    cfg2 = load_config(path)

    assert cfg1 is cfg2


def test_load_config_cache_can_be_cleared(tmp_path: Path) -> None:
    path = _write_config(tmp_path, _valid_config(secret_hex="01" * 32))

    cfg1 = load_config(path)

    new_data = _valid_config(secret_hex="02" * 32)
    path.write_text(json.dumps(new_data), encoding="utf-8")

    cfg_cached = load_config(path)
    assert cfg_cached is cfg1
    assert cfg_cached.secret == bytes.fromhex("01" * 32)

    load_config.cache_clear()
    cfg2 = load_config(path)
    assert cfg2.secret == bytes.fromhex("02" * 32)
