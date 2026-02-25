"""Minimal JWT utilities implemented using standard library.

This module creates and verifies JWTs using HS256 (HMAC-SHA256)
without relying on external JWT libraries. It also provides helper
functions to generate opaque refresh tokens.

Security notes:
- In production, use a well-maintained JWT library and keep the secret
  in an environment variable or secret manager.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode('ascii')


def _b64url_decode(data: str) -> bytes:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def encode_jwt(payload: dict, secret: str | bytes) -> str:
    """Encode a JWT with HS256.

    The caller is responsible for including an integer "exp" timestamp
    (seconds since epoch) in the payload for expiration handling.
    """
    if isinstance(secret, str):
        secret = secret.encode('utf-8')

    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_b = json.dumps(payload, separators=(',', ':'), default=str).encode('utf-8')

    segments = [
        _b64url_encode(header_b),
        _b64url_encode(payload_b),
    ]
    signing_input = '.'.join(segments).encode('utf-8')
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    segments.append(_b64url_encode(signature))
    return '.'.join(segments)


class JWTError(Exception):
    pass


class ExpiredSignatureError(JWTError):
    pass


def decode_jwt(token: str, secret: str | bytes, verify_exp: bool = True) -> dict:
    """Decode and verify a JWT. Raises `JWTError` on any invalid token.

    If `verify_exp` is True, an `ExpiredSignatureError` is raised when the
    token has expired.
    """
    if isinstance(secret, str):
        secret = secret.encode('utf-8')

    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise JWTError('Malformed token')

    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = _b64url_decode(sig_b64)
    expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_sig):
        raise JWTError('Invalid signature')

    payload_json = _b64url_decode(payload_b64)
    try:
        payload = json.loads(payload_json)
    except Exception:
        raise JWTError('Invalid payload')

    if verify_exp:
        exp = payload.get('exp')
        if exp is None:
            raise JWTError('exp claim required')
        now = int(time.time())
        if now >= int(exp):
            raise ExpiredSignatureError('Token has expired')

    return payload


def generate_access_token(user) -> tuple[str, int]:
    """Return (token, exp_timestamp).

    The token payload contains `user_id` and `username` for convenience.
    """
    now = int(time.time())
    lifetime = int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 300))
    exp = now + lifetime
    payload = {
        'user_id': int(user.pk),
        'username': getattr(user, 'email', str(user)),
        'exp': exp,
    }
    token = encode_jwt(payload, settings.JWT_SECRET)
    return token, exp


def generate_refresh_token() -> tuple[str, datetime]:
    """Create a secure opaque refresh token and expiration datetime."""
    lifetime = int(getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 60 * 60 * 24 * 7))
    token = secrets.token_urlsafe(64)
    expires_at = timezone.now() + timedelta(seconds=lifetime)
    return token, expires_at
