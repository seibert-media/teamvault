from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import ugettext as _

from ..accounts.models import Team
from .exceptions import PermissionError
from .utils import generate_password


def _generate_id_token():
    return generate_password(length=32, alphanum=True)


class Password(models.Model):
    STATUS_OK = 1
    STATUS_NEEDS_CHANGING = 2
    STATUS_DELETED = 3
    STATUS_CHOICES = (
        (STATUS_OK, _("OK")),
        (STATUS_NEEDS_CHANGING, _("needs changing")),
        (STATUS_DELETED, _("deleted")),
    )
    VISIBILITY_NAMEONLY = 1
    VISIBILITY_ANY = 2
    VISIBILITY_HIDDEN = 3
    VISIBILITY_CHOICES = (
        (VISIBILITY_NAMEONLY, _("default")),
        (VISIBILITY_ANY, _("everyone")),
        (VISIBILITY_HIDDEN, _("hidden")),
    )
    created = models.DateTimeField(auto_now_add=True)
    current_revision = models.ForeignKey(
        'PasswordRevision',
        blank=True,
        null=True,
        related_name='_password_current_revision',
    )
    description = models.TextField(
        blank=True,
        null=True,
    )
    id_token = models.CharField(
        default=_generate_id_token,
        max_length=32,
        unique=True,
    )
    last_modified = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=92)
    needs_changing_on_leave = models.BooleanField(
        default=True,
    )
    status = models.PositiveSmallIntegerField(
        default=STATUS_OK,
    )
    teams = models.ManyToManyField(
        Team,
    )
    users = models.ManyToManyField(
        get_user_model(),
        related_name='passwords',
    )
    visibility = models.PositiveSmallIntegerField(
        choices=VISIBILITY_CHOICES,
        default=VISIBILITY_NAMEONLY,
    )

    def get_password(self, user):
        if not self.is_readable_by_user(user):
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({token})"
            ).format(
                name=self.name,
                token=self.id_token,
                user=user.username,
            ))
        f = Fernet(settings.SHELDON_SECRET_KEY)
        self.current_revision.accessed_by.add(user)
        self.current_revision.save()
        return f.decrypt(self.current_revision.encrypted_password)

    def is_readable_by_user(self, user):
        """
        'Readable' means user can access the actual secret password.
        """
        if self.visibility == self.VISIBILITY_ALL:
            return True
        if user in self.users.all():
            return True
        for team in self.teams.all():
            if user in team.members.all():
                return True
        return False

    def is_visible_to_user(self, user):
        if self.visibility != self.VISIBILITY_HIDDEN:
            return True
        if user in self.users.all():
            return True
        for team in self.teams.all():
            if user in team.members.all():
                return True
        return False

    def set_password(self, user, new_password):
        if not self.is_readable_by_user(user):
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({token})"
            ).format(
                name=self.name,
                token=self.id_token,
                user=user.username,
            ))
        p = PasswordRevision()
        p.accessed_by.add(user)
        p.password = self
        p.set_by = user
        f = Fernet(settings.SHELDON_SECRET_KEY)
        p.encrypted_password = f.encrypt(new_password)
        p.save()
        self.password = p
        self.save()


class PasswordRevision(models.Model):
    accessed_by = models.ManyToManyField(
        get_user_model(),
    )
    created = models.DateTimeField(auto_now_add=True)
    encrypted_password = models.TextField()
    password = models.ForeignKey(
        Password,
    )
    set_by = models.ForeignKey(
        get_user_model(),
        related_name='password_revisions_set',
    )

    class Meta:
        # Consider the following scenario:
        # 1. an employee reads a password, it is "secret123"
        # 2. the password is changed to "secret234"
        # 3. the password is changed back to "secret123"
        # even though the employee never read the third instance of the
        # password, they still know the password from step 1.
        # This unique_together forces passwords 1 and 3 to be the same
        # database object, retaining accessed_by. This way, when the
        # employee leaves, password 3 is correctly assumed known by
        # the employee.
        unique_together = (('encrypted_password', 'password'),)
