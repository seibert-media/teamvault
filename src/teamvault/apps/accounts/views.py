from json import dumps

from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse


@login_required
def search_groups(request):
    search_term = request.GET['q']
    search_result = {'results': []}
    groups = Group.objects.filter(name__icontains=search_term)
    for group in groups:
        search_result['results'].append({'id': group.id, 'text': group.name})
    return HttpResponse(dumps(search_result), content_type="application/json")


@login_required
def search_users(request):
    search_term = request.GET['q']
    search_result = {'results': []}
    users = User.objects.filter(
        is_active=True,
        username__icontains=search_term,
    )
    for user in users:
        search_result['results'].append({'id': user.id, 'text': user.username})
    return HttpResponse(dumps(search_result), content_type="application/json")
