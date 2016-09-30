from django.conf.urls import include, url
from django.contrib import admin

admin.autodiscover()

handler404 = 'teamvault.views.handler404'

urlpatterns = (
    url(r'^api/', include('teamvault.apps.secrets.api_urls'), name='api'),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'', include('teamvault.apps.secrets.urls'), name='secrets'),
    url(r'', include('teamvault.apps.accounts.urls'), name='accounts'),
)
