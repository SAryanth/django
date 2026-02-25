"""Authentication views: login, refresh, logout and an example protected view."""
from __future__ import annotations

from datetime import datetime

from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response

from .serializers import LoginSerializer, RefreshSerializer
from .jwt_utils import generate_access_token, generate_refresh_token
from .models import RefreshToken as RefreshTokenModel


class LoginView(APIView):
    """Authenticate user and return access + refresh tokens.

    POST: { "email": "...", "password": "..." }
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = authenticate(request, username=email, password=password)
        if user is None:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        access_token, access_exp = generate_access_token(user)
        refresh_token, refresh_expires_at = generate_refresh_token()

        # Persist refresh token so it can be revoked on logout
        RefreshTokenModel.objects.create(
            user=user, token=refresh_token, expires_at=refresh_expires_at
        )

        return Response(
            {
                'access_token': access_token,
                'access_token_expires_at': datetime.utcfromtimestamp(access_exp).isoformat() + 'Z',
                'refresh_token': refresh_token,
                'refresh_token_expires_at': refresh_expires_at.isoformat(),
                'token_type': 'Bearer',
            }
        )


class RefreshView(APIView):
    """Exchange a valid refresh token for a new access token (and rotate refresh).

    POST: { "refresh_token": "..." }
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['refresh_token']

        now = timezone.now()
        try:
            rt = RefreshTokenModel.objects.get(token=token, revoked=False)
        except RefreshTokenModel.DoesNotExist:
            return Response({'detail': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        if rt.expires_at <= now:
            return Response({'detail': 'Refresh token expired'}, status=status.HTTP_401_UNAUTHORIZED)

        # rotate: revoke old refresh and issue a new one
        rt.revoked = True
        rt.save(update_fields=['revoked'])

        new_refresh, new_expires = generate_refresh_token()
        RefreshTokenModel.objects.create(user=rt.user, token=new_refresh, expires_at=new_expires)

        access_token, access_exp = generate_access_token(rt.user)

        return Response(
            {
                'access_token': access_token,
                'access_token_expires_at': datetime.utcfromtimestamp(access_exp).isoformat() + 'Z',
                'refresh_token': new_refresh,
                'refresh_token_expires_at': new_expires.isoformat(),
                'token_type': 'Bearer',
            }
        )


class LogoutView(APIView):
    """Invalidate a refresh token (logout).

    POST: { "refresh_token": "..." }
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = RefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['refresh_token']

        try:
            rt = RefreshTokenModel.objects.get(token=token)
        except RefreshTokenModel.DoesNotExist:
            return Response(status=status.HTTP_204_NO_CONTENT)

        rt.revoked = True
        rt.save(update_fields=['revoked'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProtectedExampleView(APIView):
    """A simple protected endpoint that requires a valid access token."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({'detail': 'Success', 'user_id': user.pk, 'username': getattr(user, 'email', str(user))})
from django.shortcuts import render

# Create your views here.
