from django.db import models
from django.utils.translation import gettext_lazy as _

class AccessPolicy(models.IntegerChoices):
    DISCOVERABLE = 1, _("discoverable")
    ANY          = 2, _("everyone")
    HIDDEN       = 3, _("hidden")


class SecretStatus(models.IntegerChoices):
    OK             = 1, _("OK")
    NEEDS_CHANGING = 2, _("needs changing")
    DELETED        = 3, _("deleted")

class ContentType(models.IntegerChoices):
    PASSWORD = 1, _("Password")
    CC = 2, _("Credit Card")
    FILE = 3, _("File")
