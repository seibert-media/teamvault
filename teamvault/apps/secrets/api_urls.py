from django.urls import path

from .api import SecretDetail, SecretList, SecretRevisionDetail, data_get


urlpatterns = (
    path(
        'secrets/',
        SecretList.as_view(),
        name='api.secret_list',
    ),
    path(
        'secrets/<str:hashid>/',
        SecretDetail.as_view(),
        name='api.secret_detail',
    ),
    path(
        'secret-revisions/<str:hashid>/',
        SecretRevisionDetail.as_view(),
        name='api.secret-revision_detail',
    ),
    path(
        'secret-revisions/<str:hashid>/data',
        data_get,
        name='api.secret-revision_data',
    ),
)
