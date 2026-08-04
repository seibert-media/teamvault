from pathlib import Path

from django.conf.urls import include
from django.http import HttpResponse
from django.urls import path

from teamvault.api.v2.ninja import api as api_v2

handler404 = 'teamvault.views.handler404'

# Source of truth for the migration guide; also referenced by the v1 deprecation `Link` header.
MIGRATION_GUIDE_PATH = Path(__file__).resolve().parent / 'api' / 'v2' / 'MIGRATION.md'


def migration_guide(_request):
    """Serve the v2 migration guide as markdown (public; the deprecation Link header targets it)."""
    return HttpResponse(MIGRATION_GUIDE_PATH.read_text(encoding='utf-8'), content_type='text/markdown; charset=utf-8')


urlpatterns = (
    path('api/v2/MIGRATION.md', migration_guide, name='api-v2-migration-guide'),
    path('api/v2/', api_v2.urls),
    path('api/', include('teamvault.apps.secrets.api.urls'), name='api'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('audit', include('teamvault.apps.audit.urls'), name='audit'),
    path('', include('teamvault.apps.secrets.urls'), name='secrets'),
    path('', include('teamvault.apps.accounts.urls'), name='accounts'),
    path('', include('social_django.urls', namespace='social')),
)
