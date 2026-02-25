from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone
from django.conf import settings

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
	"""Custom user model that uses email as the unique identifier."""

	email = models.EmailField(unique=True)
	first_name = models.CharField(max_length=150, blank=True)
	last_name = models.CharField(max_length=150, blank=True)

	is_staff = models.BooleanField(default=False)
	is_active = models.BooleanField(default=True)
	date_joined = models.DateTimeField(default=timezone.now)

	objects = UserManager()

	USERNAME_FIELD = 'email'
	REQUIRED_FIELDS = ['first_name', 'last_name']

	def __str__(self) -> str:
		return self.email


class RefreshToken(models.Model):
	"""Stores refresh tokens for users.

	Refresh tokens are opaque random strings that can be revoked. We store
	an expiration and a revoked flag to support logout and rotation.
	"""

	user = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		related_name='refresh_tokens',
	)
	token = models.CharField(max_length=255, unique=True)
	created_at = models.DateTimeField(auto_now_add=True)
	expires_at = models.DateTimeField()
	revoked = models.BooleanField(default=False)

	def __str__(self) -> str:
		return f"RefreshToken(user_id={self.user_id}, revoked={self.revoked})"
