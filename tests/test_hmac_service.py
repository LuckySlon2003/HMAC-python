import hashlib
import hmac

import pytest

import src.hmac_service as hs


@pytest.fixture(autouse=True)
def patch_config(monkeypatch: pytest.MonkeyPatch):
    hs.load_config.cache_clear()

    secret = bytes.fromhex("0a" * 32)

    class Cfg:
        hmac_alg = "SHA256"
        secret = b''

    Cfg.secret = secret

    monkeypatch.setattr(hs, "CONFIG_FILE", "dummy.json")
    monkeypatch.setattr(hs, "load_config", lambda _path: Cfg)

    return secret


def test_sign_matches_reference_hmac(patch_config: bytes) -> None:
    signer = hs.HMACSigner()
    msg = "hello"

    expected = hmac.new(patch_config, msg.encode(
        "utf-8"), hashlib.sha256).digest()
    assert signer.sign(msg) == expected


def test_verify_true_for_valid_signature(patch_config: bytes) -> None:
    signer = hs.HMACSigner()
    msg = "payload"

    sig = signer.sign(msg)
    assert signer.verify(msg, sig) is True


def test_verify_false_for_invalid_signature(patch_config: bytes) -> None:
    signer = hs.HMACSigner()
    assert signer.verify("payload", b"\x00" * 32) is False


def test_sign_type_error(patch_config: bytes) -> None:
    signer = hs.HMACSigner()
    with pytest.raises(TypeError):
        signer.sign(123)  # type: ignore[arg-type]


def test_verify_type_errors(patch_config: bytes) -> None:
    signer = hs.HMACSigner()

    with pytest.raises(TypeError):
        signer.verify(123, b"\x00")  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        signer.verify("ok", "nope")  # type: ignore[arg-type]
