from django.forms import Form
from django.http import HttpResponse
from django.test import TestCase
from django.test.utils import ContextList


class BaseTestCase(TestCase):
    def assertFormValid(self, response: HttpResponse):
        context: ContextList | None = getattr(response, 'context', None)
        if not context:
            return

        form: Form = context.get('form')
        if form and not form.is_valid():
            errors = form.errors.as_json()
            self.fail(f'Form errors: {errors}')
