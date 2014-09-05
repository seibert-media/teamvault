from django import forms

class AddPasswordForm(forms.Form):
    name = forms.CharField()
