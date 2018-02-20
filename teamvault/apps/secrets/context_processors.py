from ... import VERSION_STRING
from .models import AccessRequest


def access_request_count(request):
    if request.user.is_authenticated:
        return {
            'access_request_count': AccessRequest.objects.filter(
                reviewers=request.user,
                status=AccessRequest.STATUS_PENDING,
            ).count(),
        }
    else:
        return {}


def version(request):
    return {'version': VERSION_STRING}
