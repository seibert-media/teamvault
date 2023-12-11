from django.conf.urls import include
from django.urls import path

handler404 = 'teamvault.views.handler404'

urlpatterns = (
    path('api/', include('teamvault.apps.secrets.api.urls'), name='api'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('audit', include('teamvault.apps.audit.urls'), name='audit'),
    path('', include('teamvault.apps.secrets.urls'), name='secrets'),
    path('', include('teamvault.apps.accounts.urls'), name='accounts'),
    path('', include('social_django.urls', namespace='social')),
)
