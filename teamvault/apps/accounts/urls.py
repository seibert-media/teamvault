from django.conf.urls import url
from django.contrib.auth.views import LoginView, LogoutView

from . import views

urlpatterns = (
    url(
        r'^login$',
        LoginView.as_view(template_name="accounts/login.html"),
        name='accounts.login',
    ),
    url(
        r'^logout$',
        LogoutView.as_view(template_name="accounts/logout.html"),
        name='accounts.logout',
    ),
    url(
        r'^search/groups$',
        views.search_groups,
        name='accounts.search-groups',
    ),
    url(
        r'^search/users$',
        views.search_users,
        name='accounts.search-users',
    ),
    url(
        r'^users$',
        views.users,
        name='accounts.user-list',
    ),
    url(
        r'^users/(?P<uid>\w+)$',
        views.user_detail,
        name='accounts.user-detail',
    ),
    url(
        r'^users/(?P<uid>\w+)/reactivate$',
        views.user_activate,
        name='accounts.user-reactivate',
    ),
    url(
        r'^users/(?P<uid>\w+)/deactivate$',
        views.user_activate,
        {'deactivate': True},
        name='accounts.user-deactivate',
    ),
)
