from django.conf import settings
from django.db import models


class Team(models.Model):
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='teams',
        through='Membership',
    )
    name = models.CharField(max_length=64)

    class Meta:
        ordering = ('name',)

    @property
    def admins(self):
        return self.objects.filter(membership__is_admin=True)


class Membership(models.Model):
    is_admin = models.BooleanField(
        default=False,
    )
    team = models.ForeignKey(
        Team,
        related_name='team_memberships',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='memberships',
    )
