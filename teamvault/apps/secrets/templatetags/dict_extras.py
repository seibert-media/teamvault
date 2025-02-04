from django import template

register = template.Library()

@register.filter
def dict_get(dictionary, key):
    return dictionary.get(key, '')

