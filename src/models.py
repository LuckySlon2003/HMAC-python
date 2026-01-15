"""Module with models"""

from dataclasses import dataclass


@dataclass(frozen=True)
class SignRequest:
    """Model for /sign request"""
    msg: str


@dataclass(frozen=True)
class SignResponse:
    """Model for /sign response"""
    msg: str
    signature: str


@dataclass(frozen=True)
class VerifyRequest:
    """Model for /verify request"""
    msg: str
    signature: str


@dataclass(frozen=True)
class VerifyResponse:
    """Model for /verify response"""
    ok: bool


@dataclass(frozen=True, slots=True)
class Config:
    """Model for application configuration."""
    hmac_alg: str
    secret: bytes
    log_level: str
    listen_host: str
    listen_port: int
    max_msg_size_bytes: int
