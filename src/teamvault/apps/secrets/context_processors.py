from .models import AccessRequest

def access_request_count(request):
    return {
        'access_request_count': AccessRequest.objects.filter(
            reviewers=request.user,
            status=AccessRequest.STATUS_PENDING,
        ).count(),
    }
