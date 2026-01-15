"""CLI utility to rotate HMAC secret in config.json."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

from src.constants import CONFIG_FILE


def _atomic_write_text(path: Path, text: str) -> None:
    """
    Atomically write text to a file.

    Writes to a temporary file in the same directory and then replaces the
    target file to avoid partial writes.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def rotate_secret(config_path: Path, nbytes: int = 32) -> str:
    """
    Generate a new hex secret and update config.json.

    Args:
        config_path: Path to config.json.
        nbytes: Secret size in bytes (32 bytes = 256-bit recommended).

    Returns:
        The newly generated secret as a hex string.

    Raises:
        FileNotFoundError: If config file does not exist.
        json.JSONDecodeError: If config file contains invalid JSON.
        ValueError: If config root is not an object or nbytes is invalid.
        KeyError: If 'secret' field is missing.
    """
    if nbytes <= 0:
        raise ValueError("nbytes must be > 0")

    data: Any = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config root must be a JSON object")

    if "secret" not in data:
        raise KeyError("missing required field: secret")

    new_secret = secrets.token_hex(nbytes)
    data["secret"] = new_secret

    content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    _atomic_write_text(config_path, content)

    return new_secret


def main() -> None:
    parser = ArgumentParser(prog="rotate-secret",
                            description="Rotate HMAC secret in config.json")
    parser.add_argument(
        "--config",
        default=str(CONFIG_FILE),
        help="Path to config.json (default: project config.json).",
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=32,
        help="Secret size in bytes (default: 32 = 256-bit).",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Print new secret to stdout.",
    )

    args = parser.parse_args()
    config_path = Path(args.config)

    new_secret = rotate_secret(config_path=config_path, nbytes=args.bytes)

    if args.print:
        print(new_secret)


if __name__ == "__main__":
    main()
