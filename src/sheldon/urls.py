from django.conf.urls import patterns, include, url
from django.contrib import admin
from django.views.generic import RedirectView

admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', RedirectView.as_view(pattern_name='accounts.login'), name='root'),
    url(r'^accounts/', include('sheldon.apps.accounts.urls'), name='accounts'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include('sheldon.apps.secrets.api_urls'), name='api'),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
)
