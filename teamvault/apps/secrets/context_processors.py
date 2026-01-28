from teamvault.__version__ import __version__


def version(_request):
    return {'version': __version__}
