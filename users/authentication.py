"""DRF authentication class that validates our custom JWT access tokens.

This class reads the `Authorization: Bearer <token>` header, decodes
and validates the token, and returns the corresponding user.
"""
from __future__ import annotations

from typing import Optional, Tuple

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

from .jwt_utils import decode_jwt, ExpiredSignatureError


User = get_user_model()


class JWTAuthentication(authentication.BaseAuthentication):
    """Authenticate requests using a custom HS256 JWT.

    Returns a `(user, token)` tuple on success or `None` if no
    authentication information is provided.
    """

    keyword = 'Bearer'

    def authenticate(self, request) -> Optional[Tuple[User, str]]:
        auth = authentication.get_authorization_header(request).split()
        if not auth:
            return None

        if len(auth) != 2:
            raise exceptions.AuthenticationFailed('Invalid Authorization header format')

        scheme, token = auth[0].decode('utf-8'), auth[1].decode('utf-8')
        if scheme.lower() != self.keyword.lower():
            return None

        try:
            payload = decode_jwt(token, settings.JWT_SECRET)
        except ExpiredSignatureError as exc:
            raise exceptions.AuthenticationFailed('Access token expired') from exc
        except Exception as exc:
            raise exceptions.AuthenticationFailed('Invalid access token') from exc

        user_id = payload.get('user_id')
        if user_id is None:
            raise exceptions.AuthenticationFailed('Invalid token payload')

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('User not found')

        return (user, token)
