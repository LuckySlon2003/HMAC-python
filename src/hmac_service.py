"""Module with HMAC sign functions"""

from __future__ import annotations

import hmac

from src.config import load_config
from src.constants import CONFIG_FILE, DIGEST_MAP
from src.logger import get_logger

logger = get_logger(__name__)


class HMACSigner:
    """Class for HMAC sign and verify signature"""

    def __init__(self) -> None:
        cfg = load_config(CONFIG_FILE)
        self._secret: bytes = cfg.secret
        self._digestmod = DIGEST_MAP[cfg.hmac_alg]

    def sign(self, msg: str) -> bytes:
        """
        Sign message with HMAC algorithm.

        :param msg: Message for sign.
        :return: Signature bytes.
        """
        logger.debug("Signing message")

        if not isinstance(msg, str):
            logger.warning("Msg must be string")
            raise TypeError("msg must be str")

        msg_bytes = msg.encode("utf-8")
        return hmac.new(self._secret, msg_bytes, self._digestmod).digest()

    def verify(self, msg: str, signature: bytes) -> bool:
        """
        Verify message signature with HMAC algorithm.

        :param msg: Message for verify.
        :param signature: Signature for verify.
        :return: True if signature for message valid, else False.
        """
        logger.debug("Verifying signature")

        if not isinstance(msg, str):
            logger.warning("Msg must be string")
            raise TypeError("msg must be str")
        if not isinstance(signature, (bytes, bytearray)):
            logger.warning("Signature must be bytes")
            raise TypeError("signature must be bytes")

        expected = self.sign(msg)

        return hmac.compare_digest(expected, signature)


def hmac_service() -> HMACSigner:
    """
    Fabric for signer.

    :return: Initialized HMACSigner object.
    """
    return HMACSigner()
