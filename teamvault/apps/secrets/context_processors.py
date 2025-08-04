from teamvault.__version__ import __version__


def version(request):  # noqa: ARG001
    return {'version': __version__}
