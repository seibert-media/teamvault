from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from . import views

urlpatterns = (
    path(
        'login',
        LoginView.as_view(template_name="accounts/login.html"),
        name='accounts.login',
    ),
    path(
        'logout',
        LogoutView.as_view(template_name="accounts/logout.html"),
        name='accounts.logout',
    ),
    path(
        'users',
        views.users,
        name='accounts.user-list',
    ),
    path(
        'users/<str:uid>/',
        views.user_detail,
        name='accounts.user-detail',
    ),
    path(
        'users/<str:uid>/reactivate',
        views.user_activate,
        name='accounts.user-reactivate',
    ),
    path(
        'users/<str:uid>/deactivate',
        views.user_activate,
        {'deactivate': True},
        name='accounts.user-deactivate',
    ),
)
