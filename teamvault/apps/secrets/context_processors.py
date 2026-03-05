from importlib import metadata


def version(_request):
    return {'version': metadata.version('teamvault')}
