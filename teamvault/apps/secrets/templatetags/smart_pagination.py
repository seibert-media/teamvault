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
        if '__' in k:
            k, subk = k.split('__')
            querylist = querydict.getlist(k)
            if v is None:
                querylist.remove(subk)
            querydict.setlist(k, querylist)
        elif v is not None:
            querydict[k] = str(v)
        elif k in querydict:
            querydict.pop(k)
    qs = querydict.urlencode(safe='/')
    if qs:
        return '?' + qs
    else:
        return ''


@register.simple_tag()
def querystring_remove(request, key, value):
    """
    Removes a param from a list in a querystring.
    """
    querydict = request.GET.copy()

    if value in querydict.getlist(key, []):
        querylist = querydict.getlist(key)
        querylist.remove(value)
        querydict.setlist(key, querylist)

    qs = querydict.urlencode(safe='/')

    print(querydict)
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
