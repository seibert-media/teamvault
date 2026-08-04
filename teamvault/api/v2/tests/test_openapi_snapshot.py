import json
from pathlib import Path

from django.test import SimpleTestCase
from ninja.responses import NinjaJSONEncoder

from teamvault.api.v2.ninja import api

SNAPSHOT_PATH = Path(__file__).resolve().parent.parent / 'openapi.snapshot.json'
REGENERATE_HINT = (
    'Regenerate with: TEAMVAULT_CONFIG_FILE=teamvault.cfg uv run teamvault/manage.py export_openapi_schema'
    ' --api teamvault.api.v2.ninja.api --output teamvault/api/v2/openapi.snapshot.json --indent 2'
)


class OpenApiSnapshotTest(SimpleTestCase):
    """Locks the public OpenAPI contract: any schema change must be committed consciously.

    The spec is consumed by agents/MCP, so accidental contract drift is a breaking change.
    """

    def test_schema_matches_committed_snapshot(self):
        self.assertTrue(SNAPSHOT_PATH.exists(), f'OpenAPI snapshot missing. {REGENERATE_HINT}')
        snapshot = json.loads(SNAPSHOT_PATH.read_text())
        current = json.loads(json.dumps(api.get_openapi_schema(), cls=NinjaJSONEncoder))
        self.assertEqual(current, snapshot, f'OpenAPI schema changed. If intentional: {REGENERATE_HINT}')
