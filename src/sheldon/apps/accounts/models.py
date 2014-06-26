from django.contrib.auth import get_user_model
from django.db import models


class Team(models.Model):
    members = models.ManyToManyField(
        get_user_model(),
        related_name='teams',
        through='Membership',
    )
    name = models.CharField(max_length=64)

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
        get_user_model(),
        related_name='memberships',
    )
