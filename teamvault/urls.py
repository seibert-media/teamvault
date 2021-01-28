from django.conf.urls import include, url

handler404 = 'teamvault.views.handler404'

urlpatterns = (
    url(r'^api/', include('teamvault.apps.secrets.api_urls'), name='api'),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^audit', include('teamvault.apps.audit.urls'), name='audit'),
    url(r'', include('teamvault.apps.secrets.urls'), name='secrets'),
    url(r'', include('teamvault.apps.accounts.urls'), name='accounts'),
    url(r'', include('social_django.urls', namespace='social')),
)
