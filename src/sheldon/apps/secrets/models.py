from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from ..audit.auditlog import log
from .exceptions import PermissionError
from .utils import generate_password


def _generate_id_token():
    return generate_password(length=32, alphanum=True)


class AccessRequest(models.Model):
    STATUS_PENDING = 1
    STATUS_REJECTED = 2
    STATUS_APPROVED = 3
    STATUS_CHOICES = (
        (STATUS_PENDING, _("pending")),
        (STATUS_REJECTED, _("rejected")),
        (STATUS_APPROVED, _("approved")),
    )

    closed = models.DateTimeField(
        blank=True,
        null=True,
    )
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='access_requests_closed',
    )
    created = models.DateTimeField(auto_now_add=True)
    password = models.ForeignKey(
        'Password',
        related_name='access_requests',
    )
    reason_request = models.TextField(
        blank=True,
        null=True,
    )
    reason_rejected = models.TextField(
        blank=True,
        null=True,
    )
    requester = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='access_requests_created',
    )
    reviewers = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='access_requests_reviewed',
    )
    status = models.PositiveSmallIntegerField(
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )

    class Meta:
        ordering = ('-created',)


class Password(models.Model):
    ACCESS_NAMEONLY = 1
    ACCESS_ANY = 2
    ACCESS_HIDDEN = 3
    ACCESS_CHOICES = (
        (ACCESS_NAMEONLY, _("default")),
        (ACCESS_ANY, _("everyone")),
        (ACCESS_HIDDEN, _("hidden")),
    )
    STATUS_OK = 1
    STATUS_NEEDS_CHANGING = 2
    STATUS_DELETED = 3
    STATUS_CHOICES = (
        (STATUS_OK, _("OK")),
        (STATUS_NEEDS_CHANGING, _("needs changing")),
        (STATUS_DELETED, _("deleted")),
    )

    access_policy = models.PositiveSmallIntegerField(
        choices=ACCESS_CHOICES,
        default=ACCESS_NAMEONLY,
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
    groups = models.ManyToManyField(
        Group,
    )
    id_token = models.CharField(
        default=_generate_id_token,
        max_length=32,
        unique=True,
    )
    last_read = models.DateTimeField(
        default=now,
    )
    name = models.CharField(max_length=92)
    needs_changing_on_leave = models.BooleanField(
        default=True,
    )
    status = models.PositiveSmallIntegerField(
        choices=STATUS_CHOICES,
        default=STATUS_OK,
    )
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='passwords',
    )

    class Meta:
        ordering = ('name',)

    def get_password(self, user):
        if not self.is_readable_by_user(user):
            log(_(
                    "{user} tried to access '{name}' ({id}) without permission"
                ).format(
                    id=self.id_token,
                    name=self.name,
                    user=user.username,
                ),
                actor=user,
                level='warn',
                password=self,
            )
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({token})"
            ).format(
                name=self.name,
                token=self.id_token,
                user=user.username,
            ))
        f = Fernet(settings.SHELDON_SECRET_KEY)
        log(_(
                "{user} read '{name}' ({id}:{revision})"
            ).format(
                id=self.id_token,
                name=self.name,
                revision=self.current_revision.id,
                user=user.username,
            ),
            actor=user,
            level='info',
            password=self,
            password_revision=self.current_revision,
        )
        self.current_revision.accessed_by.add(user)
        self.current_revision.save()
        self.last_read = now()
        self.save()
        return f.decrypt(self.current_revision.encrypted_password)

    @classmethod
    def get_all_visible_to_user(cls, user):
        q = cls.objects.filter(users__pk=user.pk)
        q += cls.objects.filter(groups__users__pk=user.pk)
        return q.distinct()

    def is_readable_by_user(self, user):
        """
        'Readable' means user can access the actual secret password.
        """
        if self.visibility == self.ACCESS_ANY:
            return True
        if user in self.users.all():
            return True
        for group in self.groups.all():
            if user in group.members.all():
                return True
        return False

    def is_visible_to_user(self, user):
        if self.visibility != self.ACCESS_HIDDEN:
            return True
        if user in self.users.all():
            return True
        for group in self.groups.all():
            if user in group.members.all():
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
        f = Fernet(settings.SHELDON_SECRET_KEY)
        encrypted_password = f.encrypt(new_password)
        try:
            # see the comment on unique_together for PasswordRevision
            p = PasswordRevision.objects.get(
                encrypted_password=encrypted_password,
                password=self,
            )
        except PasswordRevision.DoesNotExist:
            p = PasswordRevision()
        p.accessed_by.add(user)
        p.encrypted_password = encrypted_password
        p.password = self
        p.set_by = user
        p.save()
        if self.current_revision:
            previous_revision_id = self.current_revision.id
        else:
            previous_revision_id = _("none")
        self.current_revision = p
        self.last_read = now()
        self.save()
        log(_(
                "{user} set a new password for '{name}' ({id}:{oldrev}->{newrev})"
            ).format(
                id=self.id_token,
                name=self.name,
                newrev=self.current_revision.id,
                oldrev=previous_revision_id,
                user=user.username,
            ),
            actor=user,
            level='info',
            password=self,
            password_revision=self.current_revision,
        )


class PasswordRevision(models.Model):
    accessed_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
    )
    created = models.DateTimeField(auto_now_add=True)
    encrypted_password = models.TextField()
    password = models.ForeignKey(
        Password,
    )
    set_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='password_revisions_set',
    )

    class Meta:
        ordering = ('-created',)
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
