from django import forms

class AddSecretForm(forms.Form):
    name = forms.CharField()
