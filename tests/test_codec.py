import base64
import binascii

import pytest

from src.codec import decode_base64urlsafe, encode_base64urlsafe


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a",
        b"ab",
        b"abc",
        b"hello",
        b"\x00\x01\x02\xff",
        bytes(range(0, 256)),
    ],
)
def test_encode_decode_roundtrip(data: bytes) -> None:
    encoded = encode_base64urlsafe(data)
    decoded = decode_base64urlsafe(encoded)
    assert decoded == data


def test_encode_returns_str_without_padding() -> None:
    data = b"ab"
    encoded = encode_base64urlsafe(data)

    assert isinstance(encoded, str)
    assert "=" not in encoded

    assert decode_base64urlsafe(encoded) == data


def test_encode_is_urlsafe() -> None:
    data = b"\xfb\xef\xff"
    encoded = encode_base64urlsafe(data)

    assert "+" not in encoded
    assert "/" not in encoded


def test_decode_accepts_unpadded_base64url() -> None:
    raw = b"abcd"
    enc_with_padding = base64.urlsafe_b64encode(raw).decode("ascii")
    assert enc_with_padding.endswith("==")

    enc_without_padding = enc_with_padding.rstrip("=")
    assert decode_base64urlsafe(enc_without_padding) == raw


def test_encode_accepts_bytearray() -> None:
    data = bytearray(b"hello")
    encoded = encode_base64urlsafe(data)
    assert decode_base64urlsafe(encoded) == b"hello"


def test_encode_type_error_on_non_bytes() -> None:
    with pytest.raises(TypeError):
        encode_base64urlsafe("not-bytes")  # type: ignore[arg-type]


def test_decode_type_error_on_non_str() -> None:
    with pytest.raises(TypeError):
        decode_base64urlsafe(b"not-str")  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["ab=c", "a==="])
def test_decode_invalid_base64_raises(bad: str) -> None:
    with pytest.raises((binascii.Error, ValueError)):
        decode_base64urlsafe(bad)
