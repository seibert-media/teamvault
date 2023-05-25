from django.urls import path

from . import views

urlpatterns = (
    path(
        '',
        views.dashboard,
        name='dashboard',
    ),
    path(
        'opensearch.xml',
        views.opensearch,
        name='opensearch',
    ),
    path(
        'secrets/',
        views.secret_list,
        name='secrets.secret-list',
    ),
    path(
        'secrets/<str:hashid>/',
        views.secret_detail,
        name='secrets.secret-detail',
    ),
    path(
        'secrets/<str:hashid>/delete',
        views.secret_delete,
        name='secrets.secret-delete',
    ),
    path(
        'secrets/<str:hashid>/download',
        views.secret_download,
        name='secrets.secret-download',
    ),
    path(
        'secrets/<str:hashid>/edit',
        views.secret_edit,
        name='secrets.secret-edit',
    ),
    path(
        'secrets/<str:hashid>/restore',
        views.secret_restore,
        name='secrets.secret-restore',
    ),
    path(
        'secrets/add/<str:content_type>',
        views.secret_add,
        name='secrets.secret-add',
    ),
    path(
        'secrets/live-search',
        views.secret_search,
        name='secrets.secret-search',
    ),
)
