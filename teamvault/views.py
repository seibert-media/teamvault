from django.shortcuts import render
from django.views.generic.base import ContextMixin


def handler404(request, exception, **kwargs):
    if request.user.is_authenticated:
        return render(request, "404_loggedin.html", status=404)
    else:
        return render(request, "404_anon.html", status=404)


class FilterMixin(ContextMixin):
    _bound_filter = None
    filter_class = None
    request = None

    def get_filter(self, queryset):
        if self.filter_class is None:
            raise AttributeError('No filter class specified when using FilterMixin!')

        self._bound_filter = self.filter_class(self.request.GET, queryset)
        return self._bound_filter

    def get_filtered_queryset(self, queryset):
        return self.get_filter(queryset=queryset).qs

    @staticmethod
    def manipulate_filter_form(bound_data, filter_form):
        """
        Can be overwritten in subclasses to add custom behaviour for a single view
        Has to return a filter_form
        """
        return filter_form

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        bound_filter_data = self._bound_filter.form.cleaned_data
        new_filter_form = self._bound_filter.get_form_class()()

        active_filters = {}
        initial = {}

        for field, field_data in bound_filter_data.items():
            if field_data:
                initial[field] = field_data
                if not isinstance(field_data, (tuple, list)):
                    # filter_items needs to be a list for us to iterate over
                    field_data = [field_data]

                active_filters[field] = {
                    'label': new_filter_form.fields[field].label,
                    'filter_items': field_data,
                }

        new_filter_form.initial = initial
        new_filter_form = self.manipulate_filter_form(bound_filter_data, new_filter_form)
        context.update({
            'active_filters': active_filters,
            'filter_form': new_filter_form,
            'filter': self._bound_filter,
        })
        return context
