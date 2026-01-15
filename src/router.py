"""Module with routes"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from src.codec import decode_base64urlsafe, encode_base64urlsafe
from src.hmac_service import HMACSigner, hmac_service
from src.logger import get_logger
from src.models import SignRequest, SignResponse, VerifyRequest, VerifyResponse
from src.validators import validate_msg, validate_signature

logger = get_logger(__name__)

router = APIRouter()


@router.post("/sign")
async def sign(
    request: SignRequest,
    hmac_service: Annotated[HMACSigner, Depends(hmac_service)],
) -> SignResponse:
    """
    Sign handler.

    :param request: Request model.
    :param hmac_service: HMAC service dependency.
    :return: URL safe signature for message.
    :raises HTTPException: If message invalid (empty or very big).
    """
    logger.info("Sign request received")

    validate_msg(request.msg)

    sig_bytes = hmac_service.sign(request.msg)
    logger.debug("Message signed successfully")

    return SignResponse(request.msg, encode_base64urlsafe(sig_bytes))


@router.post("/verify")
async def verify(
    request: VerifyRequest,
    hmac_service: Annotated[HMACSigner, Depends(hmac_service)],
) -> VerifyResponse:
    """
    Verify message with signature handler.

    :param request: Request model.
    :param hmac_service: HMAC service dependency.
    :return: VerifyResponse model.
    :raises HTTPException: If invalid message or signature.
    """
    logger.info("Verify request received")

    validate_msg(request.msg)
    validate_signature(request.signature)

    try:
        sig_bytes = decode_base64urlsafe(request.signature)
    except Exception as e:
        logger.warning("Signature is not valid base64url")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="signature_is_not_valid_base64url",
        ) from e

    ok = hmac_service.verify(request.msg, sig_bytes)
    logger.info("Signature verification is done")

    return VerifyResponse(ok=ok)
