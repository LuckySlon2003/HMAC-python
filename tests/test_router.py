import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.app import app
from src.codec import decode_base64urlsafe, encode_base64urlsafe

client = TestClient(app)


def _max_msg_size_bytes() -> int:
    """
    Read max_msg_size_bytes from config.json to build an oversized message.
    """
    cfg_path = Path(__file__).resolve().parent.parent / "config.json"
    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    return int(data["max_msg_size_bytes"])


def test_sign_verify_success() -> None:
    r1 = client.post("/sign", json={"msg": "hello"})
    assert r1.status_code == 200
    signature = r1.json()['signature']
    assert isinstance(signature, str)

    r2 = client.post("/verify", json={"msg": "hello", "signature": signature})
    assert r2.status_code == 200
    assert r2.json() == {"ok": True}


def test_wrong_signature_ok_false() -> None:
    r1 = client.post("/sign", json={"msg": "hello"})
    assert r1.status_code == 200
    sig = r1.json()['signature']

    sig_bytes = bytearray(decode_base64urlsafe(sig))
    sig_bytes[0] ^= 0x01
    wrong_sig = encode_base64urlsafe(bytes(sig_bytes))

    r2 = client.post("/verify", json={"msg": "hello", "signature": wrong_sig})
    assert r2.status_code == 200
    assert r2.json() == {"ok": False}


def test_changed_message_ok_false() -> None:
    r1 = client.post("/sign", json={"msg": "hello"})
    assert r1.status_code == 200
    sig = r1.json()['signature']

    r2 = client.post("/verify", json={"msg": "hello!", "signature": sig})
    assert r2.status_code == 200
    assert r2.json() == {"ok": False}


def test_invalid_base64url_signature_returns_400() -> None:
    r = client.post("/verify", json={"msg": "hello", "signature": "@@@"})
    assert r.status_code == 400
    assert r.json() == {"detail": "invalid_signature_format"}


def test_empty_msg_returns_400() -> None:
    r = client.post("/sign", json={"msg": ""})
    assert r.status_code == 400
    assert r.json() == {"detail": "invalid_msg"}


def test_big_message_returns_413() -> None:
    limit = _max_msg_size_bytes()
    big_msg = "a" * (limit + 1)

    r = client.post("/sign", json={"msg": big_msg})
    assert r.status_code == 413
