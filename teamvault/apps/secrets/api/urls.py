from django.urls import path

from .views import SecretDetail, SecretList, SecretRevisionDetail, SecretShare, SecretShareDetail, data_get, \
    generate_password_view, otp_get

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
        'secrets/<str:hashid>/shares/',
        SecretShare.as_view(),
        name='api.secret_share',
    ),
    path(
        'secrets/<str:hashid>/shares/<int:pk>',
        SecretShareDetail.as_view(),
        name='api.secret_share_detail',
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
    path(
        'secret-revisions/<str:hashid>/data/otp',
        otp_get,
        name='api.secret-revision_otp',
    ),
    path(
        'generate_password/',
        generate_password_view,
        name='api.generate-password',
    )
)
