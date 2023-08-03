from django import template
from django.shortcuts import render

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


@register.simple_tag()
def querystring_remove_item(request, key, value):
    """
    Removes item from a list in a querystring.
    """
    querydict = request.GET.copy()
    print(key, value)

    if value in querydict.getlist(key, []):
        querylist = querydict.getlist(key)
        querylist.remove(value)
        querydict.setlist(key, querylist)

    qs = querydict.urlencode(safe='/')

    if qs:
        return '?' + qs
    else:
        return ''


@register.inclusion_tag('filter/base.html')
def render_filter(request, filter_obj):
    print(request.GET)
    print(filter_obj)
    return {'filter': filter_obj}


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
