from django import template

register = template.Library()


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
