from fastapi import HTTPException, status

from src.config import load_config
from src.constants import BASE64URL_RE, CONFIG_FILE
from src.logger import get_logger

logger = get_logger(__name__)


def validate_msg(msg: str) -> None:
    """
    Validate message string and its size.

    Args:
        msg: Message to validate.

    Raises:
        HTTPException:
            - 400 if message is empty or not a string.
            - 413 if message size exceeds configured limit.
    """
    logger.debug("Validating message")

    cfg = load_config(CONFIG_FILE)

    if not isinstance(msg, str) or not msg:
        logger.warning("Invalid message")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_msg",
        )

    if len(msg.encode("utf-8")) > cfg.max_msg_size_bytes:
        logger.warning("Message too large")
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="msg_too_large",
        )


def validate_signature(signature: str) -> None:
    """
    Validate HMAC signature format.

    Signature must be a non-empty Base64URL string without padding.

    Args:
        signature: Signature string to validate.

    Raises:
        HTTPException:
            - 400 if signature is missing, not a string, or has invalid format.
    """
    logger.debug("Validating message")

    if not isinstance(signature, str) or not signature:
        logger.warning("Invalid signature")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_signature_format",
        )

    if not BASE64URL_RE.fullmatch(signature):
        logger.warning("Invalid base64url format of signature")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_signature_format",
        )
