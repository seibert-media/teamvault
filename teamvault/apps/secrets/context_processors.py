from ... import VERSION_STRING


def version(request):
    return {'version': VERSION_STRING}
