from datetime import timedelta
from enum import Enum
from hashlib import sha256
from operator import itemgetter

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models
from django.db.models import BooleanField, Case, Q, Value, When
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import Http404
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from hashids import Hashids

from .exceptions import PermissionError
from ..audit.auditlog import log
from ..audit.models import LogEntry


class AccessPermissionTypes(Enum):
    NOT_ALLOWED = 0
    ALLOWED = 1
    TEMPORARILY_ALLOWED = 2
    SUPERUSER_ALLOWED = 3


def validate_url(value):
    if "://" not in value or \
            value.startswith("javascript:") or \
            value.startswith("data:"):
        raise ValidationError(_("invalid URL"))


class HashIDModel(models.Model):
    hashid = models.CharField(
        max_length=24,
        null=True,
        unique=True,
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self.pk:
            # need to save once to get a primary key, then once again to
            # save the hashid
            super(HashIDModel, self).save(*args, **kwargs)
        if not self.hashid:
            hasher = Hashids(
                min_length=settings.HASHID_MIN_LENGTH,
                salt=self.HASHID_NAMESPACE + settings.HASHID_SALT,
            )
            self.hashid = hasher.encode(self.pk)
        # we cannot force insert anymore because we might already have
        # created the object
        kwargs['force_insert'] = False
        return super(HashIDModel, self).save(*args, **kwargs)


class Secret(HashIDModel):
    HASHID_NAMESPACE = "Secret"

    ACCESS_POLICY_DISCOVERABLE = 1
    ACCESS_POLICY_ANY = 2
    ACCESS_POLICY_HIDDEN = 3
    ACCESS_POLICY_CHOICES = (
        (ACCESS_POLICY_DISCOVERABLE, _("discoverable")),
        (ACCESS_POLICY_ANY, _("everyone")),
        (ACCESS_POLICY_HIDDEN, _("hidden")),
    )
    CONTENT_PASSWORD = 1
    CONTENT_CC = 2
    CONTENT_FILE = 3
    CONTENT_CHOICES = (
        (CONTENT_PASSWORD, _("Password")),
        (CONTENT_CC, _("Credit Card")),
        (CONTENT_FILE, _("File")),
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
        choices=ACCESS_POLICY_CHOICES,
        default=ACCESS_POLICY_DISCOVERABLE,
    )
    content_type = models.PositiveSmallIntegerField(
        choices=CONTENT_CHOICES,
        default=CONTENT_PASSWORD,
    )
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.PROTECT,
        related_name='passwords_created',
    )
    current_revision = models.ForeignKey(
        'SecretRevision',
        models.PROTECT,
        blank=True,
        null=True,
        related_name='_password_current_revision',
    )
    description = models.TextField(
        blank=True,
        null=True,
        help_text=_('Further information on the secret.'),
    )
    filename = models.CharField(
        blank=True,
        max_length=255,
        null=True,
    )
    last_changed = models.DateTimeField(
        auto_now_add=True,
    )
    last_read = models.DateTimeField(
        default=now,
    )
    name = models.CharField(max_length=92, help_text=_('Enter a unique name for the secret'))
    needs_changing_on_leave = models.BooleanField(
        default=True,
    )
    shared_groups = models.ManyToManyField(
        Group,
        blank=True,
        through='SharedSecretData',
        through_fields=('secret', 'group'),
    )
    shared_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        through='SharedSecretData',
        through_fields=('secret', 'user'),
    )
    status = models.PositiveSmallIntegerField(
        choices=STATUS_CHOICES,
        default=STATUS_OK,
    )
    url = models.CharField(
        blank=True,
        max_length=255,
        null=True,
        # Django's builtin URL validation is pretty strict to the point
        # of rejecting perfectly good URLs, thus we roll our own very
        # liberal validation
        validators=[validate_url],
    )
    username = models.CharField(
        blank=True,
        max_length=255,
        null=True,
    )

    search_index = SearchVectorField(blank=True, null=True)

    class Meta:
        ordering = ('name', 'username')

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<Secret '{name}' ({id})>".format(id=self.hashid, name=self.name)

    def check_access(self, user):
        if not self.is_visible_to_user(user):
            raise Http404

        readable = self.is_readable_by_user(user)
        if not readable:
            raise PermissionDenied()
        return readable

    @property
    def full_url(self):
        return settings.BASE_URL.rstrip("/") + self.get_absolute_url()

    def get_absolute_url(self):
        return reverse('secrets.secret-detail', args=[str(self.hashid)])

    def get_data(self, user):
        if not self.current_revision:
            raise Http404

        read_allowed = self.is_readable_by_user(user)
        if not read_allowed:
            log(
                _("{user} tried to access '{name}' without permission").format(name=self.name, user=user.username),
                actor=user,
                level='warning',
                secret=self,
            )
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({id})"
            ).format(
                id=self.id,
                name=self.name,
                user=user.username,
            ))

        if read_allowed == AccessPermissionTypes.SUPERUSER_ALLOWED:
            log_message = _("{user} used superuser privileges to read '{name}'")
        else:
            log_message = _("{user} read '{name}'")

        if self.needs_changing() and read_allowed:
            log(_(
                f'{user.username} was reminded to update {self.name}'
            ),
                actor=user,
                level='info',
                secret=self,
            )
        log(
            log_message.format(
                name=self.name,
                user=user.username,
            ),
            actor=user,
            level='info',
            secret=self,
            secret_revision=self.current_revision,
        )
        self.current_revision.accessed_by.add(user)
        self.current_revision.save()
        self.last_read = now()
        self.save()

        f = Fernet(settings.TEAMVAULT_SECRET_KEY)
        plaintext_data = f.decrypt(self.current_revision.encrypted_data.tobytes())
        if self.content_type != Secret.CONTENT_FILE:
            plaintext_data = plaintext_data.decode('utf-8')
        return plaintext_data

    @classmethod
    def get_all_readable_by_user(cls, user):
        if user.is_superuser:
            return cls.objects.all()

        allowed_shares = SharedSecretData.objects.with_expiry_state().filter(
            Q(user=user) | Q(group__user=user)
        ).exclude(is_expired=True).values('secret__pk')
        return cls.objects.filter(
            Q(access_policy=cls.ACCESS_POLICY_ANY) | Q(pk__in=allowed_shares)
        ).exclude(status=cls.STATUS_DELETED).distinct()

    @classmethod
    def get_all_visible_to_user(cls, user, queryset=None):
        if queryset is None:
            queryset = cls.objects.all()

        if user.is_superuser:
            return queryset

        allowed_shares = SharedSecretData.objects.with_expiry_state().filter(
            Q(user=user) | Q(group__user=user)
        ).exclude(is_expired=True).values('secret__pk')
        return queryset.filter(
            Q(access_policy__in=(cls.ACCESS_POLICY_ANY, cls.ACCESS_POLICY_DISCOVERABLE)) | Q(pk__in=allowed_shares)
        ).exclude(status=cls.STATUS_DELETED).distinct()

    @classmethod
    def get_most_used_for_user(cls, user, limit=5):
        since = now() - timedelta(days=90)
        accessed_secrets = LogEntry.objects.filter(
            actor=user,
            secret__isnull=False,
            time__gte=since,
        ).order_by(
            'secret'
        ).values(
            'secret'
        ).annotate(
            access_count=models.Count('secret'),
        )
        ordered_secrets = sorted(accessed_secrets, key=itemgetter('access_count'), reverse=True)
        return [cls.objects.get(id=item['secret']) for item in ordered_secrets[:limit]]

    @classmethod
    def get_most_recently_used_for_user(cls, user, limit=5):
        secrets = []
        log_entries = LogEntry.objects.filter(
            actor=user,
            secret__isnull=False,
        )
        number_of_log_entries = log_entries.count()
        offset = limit
        while len(secrets) < limit and (offset < number_of_log_entries or offset == limit):
            for log_entry in log_entries[:offset].select_related('secret'):
                if log_entry.secret not in secrets and len(secrets) < limit:
                    secrets.append(log_entry.secret)
            offset += limit
        return secrets

    @classmethod
    def get_search_results(cls, user, term, limit=None):
        base_queryset = cls.get_all_visible_to_user(user)
        name_hits = base_queryset.filter(name__icontains=term)
        fulltext_hits = cls.get_all_visible_to_user(
            user,
            queryset=cls.objects.filter(search_index=term),
        )
        substr_hits = base_queryset.filter(
            models.Q(filename__icontains=term) |
            models.Q(url__icontains=term) |
            models.Q(username__icontains=term)
        )
        if limit:
            name_hits = name_hits[:limit]
            fulltext_hits = fulltext_hits[:limit]
            substr_hits = substr_hits[:limit]
        # concatenate and remove duplicates
        result = (name_hits | fulltext_hits | substr_hits).distinct()
        if limit:
            return result[:limit]
        else:
            return result

    def is_readable_by_user(self, user):
        if self.status != self.STATUS_DELETED:
            shares = self.share_data.with_expiry_state().filter(
                Q(user=user) | Q(group__user=user)
            ).exclude(is_expired=True)

            if self.access_policy == self.ACCESS_POLICY_ANY or shares.filter(granted_until__isnull=True).exists():
                return AccessPermissionTypes.ALLOWED

            if user.is_superuser:
                return AccessPermissionTypes.SUPERUSER_ALLOWED

            if shares.exclude(granted_until__isnull=True).exists():
                return AccessPermissionTypes.TEMPORARILY_ALLOWED

        return AccessPermissionTypes.NOT_ALLOWED

    def is_shareable_by_user(self, user):
        read_permission = self.is_readable_by_user(user)
        if read_permission in [AccessPermissionTypes.ALLOWED, AccessPermissionTypes.SUPERUSER_ALLOWED]:
            return True
        return False

    def is_visible_to_user(self, user):
        if self.status != self.STATUS_DELETED:
            if (
                self.access_policy in (self.ACCESS_POLICY_ANY, self.ACCESS_POLICY_DISCOVERABLE) or
                self.is_readable_by_user(user)
            ):
                return AccessPermissionTypes.ALLOWED

        if user.is_superuser:
            return AccessPermissionTypes.SUPERUSER_ALLOWED
        return AccessPermissionTypes.NOT_ALLOWED

    def set_data(self, user, plaintext_data, skip_access_check=False):
        # skip_access_check is used when initially creating a secret
        # and makes it possible to create secrets you don't have access
        # to
        if not skip_access_check and not self.is_readable_by_user(user):
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({id})"
            ).format(
                id=self.id,
                name=self.name,
                user=user.username,
            ))
        # save the length before encoding so multi-byte characters don't
        # mess up the result
        plaintext_length = len(plaintext_data)
        if isinstance(plaintext_data, str):
            plaintext_data = plaintext_data.encode('utf-8')
        plaintext_data_sha256 = sha256(plaintext_data).hexdigest()
        f = Fernet(settings.TEAMVAULT_SECRET_KEY)
        encrypted_data = f.encrypt(plaintext_data)
        try:
            # see the comment on unique_together for SecretRevision
            p = SecretRevision.objects.get(
                plaintext_data_sha256=plaintext_data_sha256,
                secret=self,
            )
        except SecretRevision.DoesNotExist:
            p = SecretRevision()
        p.encrypted_data = encrypted_data
        p.length = plaintext_length
        # the hash is needed for unique_together (see below)
        # unique_together uses an index on its fields which is
        # problematic with the largeish blobs we might store here (see
        # issue #30)
        p.plaintext_data_sha256 = plaintext_data_sha256
        p.secret = self
        p.set_by = user
        p.save()
        p.accessed_by.add(user)
        if self.current_revision:
            previous_revision_id = self.current_revision.id
        else:
            previous_revision_id = _("none")
        self.current_revision = p
        self.last_changed = now()
        self.last_read = now()
        if self.status == self.STATUS_NEEDS_CHANGING:
            self.status = self.STATUS_OK
        self.save()
        log(_(
                "{user} set a new secret for '{name}' ({oldrev}->{newrev})"
            ).format(
                name=self.name,
                newrev=self.current_revision.id,
                oldrev=previous_revision_id,
                user=user.username,
            ),
            actor=user,
            level='info',
            secret=self,
            secret_revision=self.current_revision,
        )

    def needs_changing(self):
        return self.status == self.STATUS_NEEDS_CHANGING


class SecretRevision(HashIDModel):
    HASHID_NAMESPACE = "SecretRevision"

    accessed_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
    )
    created = models.DateTimeField(auto_now_add=True)
    encrypted_data = models.BinaryField()
    length = models.PositiveIntegerField(
        default=0,
    )
    plaintext_data_sha256 = models.CharField(
        max_length=64,
    )
    secret = models.ForeignKey(
        Secret,
        models.PROTECT,
    )
    set_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        models.PROTECT,
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
        # employee leaves, password 3 is correctly assumed known to
        # the employee.
        unique_together = (('plaintext_data_sha256', 'secret'),)

    def __repr__(self):
        return "<SecretRevision '{name}' ({id})>".format(id=self.hashid, name=self.secret.name)

    @property
    def is_current_revision(self):
        return self.secret.current_revision == self


class SecretShareQuerySet(models.QuerySet):
    # TODO: Rename to group_shares, user_shares
    def groups(self):
        return self.with_expiry_state().filter(group__isnull=False).order_by('group__name')

    def users(self):
        return self.with_expiry_state().filter(user__isnull=False).order_by('user__username')

    def with_expiry_state(self):
        return self.annotate(
            is_expired=Case(
                When(
                    granted_until__lte=now(),
                    then=Value(True)
                ),
                default=Value(False),
                output_field=BooleanField()
            )
        )


class SharedSecretData(models.Model):
    objects = SecretShareQuerySet.as_manager()

    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
        null=True,
        related_name='secret_share_data',
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        related_name='secret_share_data',
    )

    secret = models.ForeignKey(
        'Secret',
        on_delete=models.CASCADE,
        related_name='share_data',
    )

    grant_description = models.TextField(
        null=True
    )

    granted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='+',
    )

    granted_on = models.DateTimeField(
        auto_now_add=True,
        null=True,
    )

    # Secrets are considered permanently shared if granted_until is not set
    granted_until = models.DateTimeField(
        blank=True,
        null=True,
    )

    @property
    def shared_entity(self):
        return self.group if self.group else self.user

    @property
    def shared_entity_name(self):
        return self.group.name if self.group else self.user.username

    @property
    def shared_entity_type(self):
        return 'group' if self.group else 'user'

    @property
    def about_to_expire(self):
        if not self.granted_until:
            return False

        if now() + timedelta(hours=8) >= self.granted_until:
            return True

    @property
    def expiry_icon(self):
        if not self.granted_until:
            return 'success'

        if self.about_to_expire:
            time_left = self.granted_until - now()
            if time_left <= timedelta(hours=8):
                return 'danger'
        return 'warning'

    def __str__(self):
        return f'SharedSecretData object ({self.secret.name}: {self.user.username if self.user else self.group.name})'

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(
                    (Q(group__isnull=False) & Q(user__isnull=True)) |
                    (Q(group__isnull=True) & Q(user__isnull=False))
                ),
                name='only_one_set'
            ),
        ]
        unique_together = [('group', 'secret'), ('user', 'secret')]


@receiver(post_save, sender=Secret)
def update_search_index(sender, **kwargs):
    Secret.objects.filter(id=kwargs['instance'].id).update(
        search_index=(
            SearchVector('name', weight='A') +
            SearchVector('description', weight='B') +
            SearchVector('username', weight='C') +
            SearchVector('filename', weight='D')
        ),
    )
