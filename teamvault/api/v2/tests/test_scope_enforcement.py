from django.test import SimpleTestCase
from ninja import NinjaAPI, Router

from teamvault.api.v2.ninja import api


def unprotected_operations(ninja_api):
    """Operations lacking both @requires_scope and @public_endpoint."""
    unprotected = []
    for prefix, router in ninja_api._routers:
        for path, path_view in router.path_operations.items():
            for operation in path_view.operations:
                handler = operation.view_func
                has_scope = getattr(handler, '_required_scope', None) is not None
                is_public = getattr(handler, '_public_endpoint', False)
                if not has_scope and not is_public:
                    unprotected.append(f'{",".join(operation.methods)} {prefix}{path}')
    return unprotected


class ScopeEnforcementCoverageTest(SimpleTestCase):
    """Every v2 operation must either enforce a scope or be explicitly marked public.

    Load-bearing: the docs are public, so scope enforcement is the only security
    boundary. This walks the live NinjaAPI route registry, so newly added endpoints
    fail until they get @requires_scope or @public_endpoint.
    """

    def test_every_operation_declares_scope_or_is_public(self):
        self.assertEqual(
            unprotected_operations(api),
            [],
            'Operations without @requires_scope or @public_endpoint found. '
            'Every v2 endpoint must declare its required scope explicitly.',
        )

    def test_walker_detects_unprotected_operations(self):
        # Self-test: an undecorated handler must be flagged, otherwise the
        # coverage test above could silently pass on a broken walker.
        bare_api = NinjaAPI(urls_namespace='enforcement-self-test')
        bare_router = Router()

        @bare_router.get('/unprotected')
        def unprotected(request):  # noqa: ARG001 - ninja requires the first param to be named `request`
            return 'oops'

        bare_api.add_router('', bare_router)
        self.assertEqual(unprotected_operations(bare_api), ['GET /unprotected'])
