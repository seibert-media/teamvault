from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import (
    get_user_avatar_partial,
    search_user,
    user_activate,
    user_detail,
    user_detail_from_request,
    user_settings,
    users,
)

urlpatterns = (
    path(
        'login/',
        LoginView.as_view(template_name='accounts/login.html'),
        name='accounts.login',
    ),
    path(
        'logout/',
        LogoutView.as_view(template_name='accounts/logout.html'),
        name='accounts.logout',
    ),
    path(
        'users/',
        users,
        name='accounts.user-list',
    ),
    path(
        'users/avatar/',
        get_user_avatar_partial,
        name='accounts.user.avatar',
    ),
    path(
        'users/detail/',
        user_detail_from_request,
        name='accounts.user-detail-from-request',
    ),
    path(
        'users/search/',
        search_user,
        name='accounts.search-user',
    ),
    path(
        'users/<str:username>/',
        user_detail,
        name='accounts.user-detail',
    ),
    path(
        'users/<str:username>/reactivate',
        user_activate,
        name='accounts.user-reactivate',
    ),
    path(
        'users/<str:username>/deactivate',
        user_activate,
        {'deactivate': True},
        name='accounts.user-deactivate',
    ),
    path(
        'settings/',
        user_settings,
        name='accounts.user-settings',
    ),
)
