from teamvault.__version__ import __version__


def version(request):
    return {'version': __version__}
