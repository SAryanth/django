"""URL routes for authentication endpoints."""
from django.urls import path

from .views import LoginView, RefreshView, LogoutView, ProtectedExampleView

app_name = 'users'

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshView.as_view(), name='token_refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('protected/', ProtectedExampleView.as_view(), name='protected_example'),
]
