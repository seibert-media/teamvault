import functools

from ninja.errors import HttpError

VALID_SCOPES = {
    'secrets:read',
    'secrets:data:read',
    'secrets:write',
    'shares:write',
    'users:read',
}
VALID_RESOURCES = {s.split(':')[0] for s in VALID_SCOPES}


def validate_scopes(scopes: list[str]) -> None:
    for scope in scopes:
        if scope.endswith(':*'):
            resource = scope.split(':')[0]  # 'resource:*' -> 'resource'
            if resource not in VALID_RESOURCES:
                raise ValueError(f'Invalid wildcard resource: {scope}')
        elif scope not in VALID_SCOPES:
            raise ValueError(f'Invalid scope: {scope}. Valid: {",".join(sorted(VALID_SCOPES))}')


def public_endpoint(func):
    """Mark a handler as intentionally requiring no scope (authentication still applies).

    Without this marker, the scope-coverage test rejects any handler lacking @requires_scope.
    """
    func._public_endpoint = True
    return func


def requires_scope(scope: str):
    if scope not in VALID_SCOPES:
        valid = ', '.join(sorted(VALID_SCOPES))
        raise ValueError(f'Unknown scope {scope!r} used in requires_scope(). Valid: {valid}')

    def decorator(func):
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            if not request.auth.has_scope(scope):
                raise HttpError(403, f'Missing required scope: {scope}')
            return func(request, *args, **kwargs)

        wrapper._required_scope = scope  # introspectable by the scope-coverage test
        return wrapper

    return decorator
