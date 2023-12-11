from django.urls import path

from . import views

urlpatterns = (
    path(
        'log/',
        views.auditlog,
        name='audit.log',
    ),
)
