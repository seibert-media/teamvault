from django.conf.urls import url
from django.contrib import admin
from django.contrib.auth.views import login, logout

from .views import search_groups, search_users

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
        search_groups,
        name='accounts.search-groups',
    ),
    url(
        r'^search/users$',
        search_users,
        name='accounts.search-users',
    ),
)
