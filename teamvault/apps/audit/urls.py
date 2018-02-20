from django.conf.urls import url

from . import views

urlpatterns = (
    url(
        r'^log/$',
        views.auditlog,
        name='audit.log',
    ),
)
