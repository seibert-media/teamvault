from json import dumps

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.views.generic import ListView

from .models import Password


class PasswordList(ListView):
    context_object_name = 'passwords'
    template_name = "secrets/browse/passwords.html"

    def get_queryset(self):
        return Password.objects.all()


@login_required
def live_search(request):
    search_term = request.GET['q']
    search_result = []
    all_passwords = Password.get_all_visible_to_user(request.user)
    filtered_passwords = all_passwords.filter(name__contains=search_term)[:20]
    sorted_passwords = []

    # sort readable passwords to top...
    for password in filtered_passwords:
        if password.is_readable_by_user(request.user):
            sorted_passwords.append(password)

    # and others to the bottom
    for password in filtered_passwords:
        if password not in sorted_passwords:
            sorted_passwords.append(password)

    for password in sorted_passwords:
        search_result.append((
            password.name,
        ))

    return HttpResponse(dumps(search_result), content_type="application/json")

