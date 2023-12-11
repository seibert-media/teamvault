from urllib.parse import urlencode

from django import template


register = template.Library()


@register.simple_tag()
def querystring(request, **kwargs):
    """
    Append or update params in a querystring.
    """
    querydict = request.GET.copy()
    for k, v in kwargs.items():
        if v is not None:
            querydict[k] = str(v)
        elif k in querydict:
            querydict.pop(k)
    qs = querydict.urlencode(safe='/')
    if qs:
        return '?' + qs
    else:
        return ''


@register.filter
def smart_pages(all_pages, current_page):
    all_pages = list(all_pages)
    smart_pages = set([
        1,
        all_pages[-1],
        current_page,
        max(min(current_page // 2, all_pages[-1]), 1),
        max(min(current_page + ((all_pages[-1] - current_page) // 2), all_pages[-1]), 1),
        max(min(current_page + 1, all_pages[-1]), 1),
        max(min(current_page + 2, all_pages[-1]), 1),
        max(min(current_page - 1, all_pages[-1]), 1),
        max(min(current_page - 2, all_pages[-1]), 1),
    ])
    return sorted(smart_pages)
