"""Module with application exceptions."""

from fastapi import Request, status
from fastapi.responses import JSONResponse


async def request_validation_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """
    Handle request validation errors.

    Converts FastAPI validation errors (422) into HTTP 400 responses.
    """
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": exc.errors()},  # type: ignore[arg-type]
    )


class ConfigError(ValueError):
    """Raised when configuration is missing, invalid, or inconsistent."""
