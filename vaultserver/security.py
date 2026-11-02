"""Authentication, signed protocol statements, and strict input validation."""

import base64
import hashlib
import hmac
import re
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from .store import canonical, digest


ITERATIONS = 600000
MAX_FILE_SIZE = 256 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def require(condition, message, status=400):
    if not condition:
        raise ApiError(message, status)


def unb64(value):
    try:
        return base64.b64decode(value, validate=True)
    except Exception as error:
        raise ApiError("Dữ liệu Base64 không hợp lệ") from error


def unurl64(value):
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value),
        "Khóa công khai không hợp lệ",
    )
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS
    ).hex()


def new_password(password):
    salt = secrets.token_hex(32)
    return salt, password_hash(password, salt)


def check_password(password, row):
    return hmac.compare_digest(
        password_hash(password, row["salt"]), row["password_hash"]
    )


def fingerprint(public):
    identity = {
        "signing": public["signing"],
        "elgamal": public["elgamal"],
        "group": public["group"],
    }
    return digest(canonical(identity))


def validate_public(public):
    require(isinstance(public, dict), "Thiếu khóa công khai")
    jwk = public.get("signing", {})
    require(
        jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519" and "d" not in jwk,
        "Cần public key Ed25519",
    )
    require(len(unurl64(jwk.get("x", ""))) == 32, "Ed25519 key phải dài 32 byte")
    require(public.get("group") == "RFC3526-MODP3072", "Nhóm ElGamal phải là MODP3072")
    require(
        bool(re.fullmatch(r"[0-9a-f]{768}", public.get("elgamal", ""))),
        "ElGamal public key không hợp lệ",
    )
    require(public.get("fingerprint") == fingerprint(public), "Fingerprint không khớp")


def verify(public, payload, signature):
    try:
        key = Ed25519PublicKey.from_public_bytes(unurl64(public["signing"]["x"]))
        key.verify(unb64(signature), canonical(payload))
    except (InvalidSignature, ValueError, KeyError, TypeError) as error:
        raise ApiError("Chữ ký Ed25519 không hợp lệ", 400) from error


def validate_bundle(bundle):
    require(isinstance(bundle, dict), "Thiếu gói khóa mã hóa")
    require(
        bundle.get("kdf") == "PBKDF2-SHA256" and bundle.get("iterations") == ITERATIONS,
        "Sai KDF bảo vệ khóa",
    )
    require(len(unb64(bundle.get("salt", ""))) == 32, "Salt phải dài 32 byte")
    require(len(unb64(bundle.get("iv", ""))) == 12, "IV phải dài 12 byte")
    require(64 < len(unb64(bundle.get("data", ""))) < 20000, "Gói khóa không hợp lệ")


def valid_id(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[a-z]+_[0-9a-f]{32}", value))
