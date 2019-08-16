from django.shortcuts import render


def handler404(request, exception, **kwargs):
    if request.user.is_authenticated:
        return render(request, "404_loggedin.html", status=404)
    else:
        return render(request, "404_anon.html", status=404)
