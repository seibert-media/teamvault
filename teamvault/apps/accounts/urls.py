from django.conf.urls import url
from django.contrib import admin
from django.contrib.auth.views import login, logout

from . import views

admin.autodiscover()

urlpatterns = (
    url(
        r'^login$',
        login,
        {'template_name': "accounts/login.html"},
        name='accounts.login',
    ),
    url(
        r'^logout$',
        logout,
        {'template_name': "accounts/logout.html"},
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
