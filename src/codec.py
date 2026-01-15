"""Module with codec functions"""

import base64

from src.logger import get_logger

logger = get_logger(__name__)


def encode_base64urlsafe(data: bytes) -> str:
    logger.debug("Base64urlsafe encoding")

    if not isinstance(data, (bytes, bytearray)):
        logger.warning("Data must be bytes")
        raise TypeError("data must be bytes")

    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def decode_base64urlsafe(data: str) -> bytes:
    logger.debug("Base64urlsafe decoding")

    if not isinstance(data, str):
        logger.warning("Data must be string")
        raise TypeError("data must be str")

    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
