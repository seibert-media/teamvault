import base64
from datetime import timedelta
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from operator import itemgetter

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models
from django.db.models import BooleanField, Case, Max, Q, Value, When
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import Http404
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from hashids import Hashids
from pyotp import TOTP

from .exceptions import PermissionError
from ..audit.auditlog import log
from ..audit.models import AuditLogCategoryChoices, LogEntry


class AccessPermissionTypes(models.IntegerChoices):
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
    share_data: 'SecretShareQuerySet'

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

    def check_read_access(self, user):
        if not self.is_visible_to_user(user):
            raise Http404

        readable = self.is_readable_by_user(user)
        if not readable:
            raise PermissionDenied()
        return readable

    def check_share_access(self, user):
        if not self.is_visible_to_user(user):
            raise Http404

        shareable = self.is_shareable_by_user(user)
        if not shareable:
            raise PermissionDenied()
        return shareable

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
                category=AuditLogCategoryChoices.SECRET_PERMISSION_VIOLATION,
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
            category = AuditLogCategoryChoices.SECRET_ELEVATED_SUPERUSER_READ
            log_message = _("{user} used superuser privileges to read '{name}'")
        else:
            category = AuditLogCategoryChoices.SECRET_READ
            log_message = _("{user} read '{name}'")
        log(
            log_message.format(
                name=self.name,
                user=user.username,
            ),
            actor=user,
            category=category,
            level='info',
            secret=self,
            secret_revision=self.current_revision,
        )
        self.current_revision.accessed_by.add(user)
        self.current_revision.save()
        self.last_read = now()
        self.save()
        f = Fernet(settings.TEAMVAULT_SECRET_KEY)

        plaintext_data = self.current_revision.encrypted_data
        plaintext_data = f.decrypt(plaintext_data).decode('utf-8')
        try:
            plaintext_data = loads(plaintext_data)
            if self.content_type == Secret.CONTENT_FILE:
                plaintext_data = base64.b64decode(plaintext_data["file_content"])
        except JSONDecodeError:
            if self.content_type == self.CONTENT_PASSWORD:
                plaintext_data = dict(password=plaintext_data)

        return plaintext_data

    def get_otp(self, request):
        cached_otp_session_key = f'otp_key_data-{self.hashid}-{self.current_revision_id}'
        if request.session.get(cached_otp_session_key):
            data = request.session[cached_otp_session_key]
        else:
            data = self.get_data(request.user)
            request.session[cached_otp_session_key] = {'otp_key': data['otp_key'], 'digits': int(data.get('digits', 6))}
        otp_key = data['otp_key']
        digits = int(data.get('digits', 6))
        totp = TOTP(otp_key, digits=digits)
        return totp.now()

    @classmethod
    def get_all_readable_by_user(cls, user):
        if user.is_superuser and settings.ALLOW_SUPERUSER_READS:
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
        log_entries = LogEntry.objects.filter(
            actor=user
        ).values(
            'secret'
        ).annotate(
            latest_time=Max('time')
        ).order_by(
            '-latest_time'
        )[:limit]

        ordered_secret_ids = [access['secret'] for access in log_entries]
        unordered_secrets = Secret.objects.filter(id__in=ordered_secret_ids)
        secret_map = {secret.id: secret for secret in unordered_secrets}
        ordered_secrets = [secret_map[secret_id] for secret_id in ordered_secret_ids if secret_id in secret_map]
        return ordered_secrets

    @classmethod
    def get_search_results(cls, user, term, limit=None, substr_search=True):
        base_queryset = cls.get_all_visible_to_user(user)
        name_hits = base_queryset.filter(name__icontains=term)
        fulltext_hits = cls.get_all_visible_to_user(
            user,
            queryset=cls.objects.filter(search_index=term),
        )

        substr_hits = Secret.objects.none()
        if substr_search:
            substr_hits = base_queryset.filter(
                models.Q(filename__icontains=term) |
                models.Q(url__icontains=term) |
                models.Q(username__icontains=term) |
                models.Q(hashid__exact=term)
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

            if shares.exists():
                return AccessPermissionTypes.TEMPORARILY_ALLOWED

        if user.is_superuser and settings.ALLOW_SUPERUSER_READS:
            return AccessPermissionTypes.SUPERUSER_ALLOWED

        return AccessPermissionTypes.NOT_ALLOWED

    def is_shareable_by_user(self, user):
        read_permission = self.is_readable_by_user(user)
        if read_permission == AccessPermissionTypes.ALLOWED:
            return AccessPermissionTypes.ALLOWED

        if user.is_superuser:
            return AccessPermissionTypes.SUPERUSER_ALLOWED
        return AccessPermissionTypes.NOT_ALLOWED

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
        set_password = self.content_type == Secret.CONTENT_PASSWORD and "password" in plaintext_data
        set_otp = self.content_type == Secret.CONTENT_PASSWORD and "otp_key" in plaintext_data
        plaintext_length = len(plaintext_data)
        f = Fernet(settings.TEAMVAULT_SECRET_KEY)
        if set_password:
            plaintext_data_sha256 = sha256(plaintext_data["password"].encode('utf-8')).hexdigest()
        else:
            plaintext_data_sha256 = sha256(dumps(plaintext_data).encode('utf-8')).hexdigest()
        try:
            # see the comment on unique_together for SecretRevision
            p = SecretRevision.objects.get(
                plaintext_data_sha256=plaintext_data_sha256,
                secret=self,
            )
        except SecretRevision.DoesNotExist:
            p = SecretRevision()
        if self.current_revision and self.content_type == Secret.CONTENT_PASSWORD:
            old_data = f.decrypt(self.current_revision.encrypted_data).decode('utf-8')
            # If not already dict convert to dict since password and otp key are now stored together in dict format.
            # To keep everything uniform CC and file secrets stored as a dict as well
            try:
                old_data = loads(old_data)
            except JSONDecodeError:
                old_data = dict(password=old_data)
            if not set_password:
                plaintext_data["password"] = old_data["password"]
            if not set_otp and "otp_key" in old_data:
                for key in ["otp_key", "digits", "algorithm"]:
                    if key in old_data:
                        plaintext_data[key] = old_data[key]
                        set_otp = True

        if self.content_type == Secret.CONTENT_PASSWORD and "password" in plaintext_data.keys():
            plaintext_length = len(plaintext_data["password"])
        if set_otp:
            p.otp_key_set = True
        plaintext_data = dumps(plaintext_data).encode("utf-8")

        p.encrypted_data = f.encrypt(plaintext_data)
        p.length = plaintext_length
        p.plaintext_data_sha256 = plaintext_data_sha256
        p.set_by = user
        p.secret = self
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
        log(
            _("{user} set a new secret for '{name}' ({oldrev}->{newrev})").format(
                name=self.name,
                newrev=self.current_revision.id,
                oldrev=previous_revision_id,
                user=user.username,
            ),
            actor=user,
            category=AuditLogCategoryChoices.SECRET_CHANGED,
            level='info',
            secret=self,
            secret_revision=self.current_revision,
        )

    def needs_changing(self):
        return self.status == self.STATUS_NEEDS_CHANGING

    def share(self, grant_description, granted_by, user=None, group=None, granted_until=None):
        if (user and group) or (not user and not group):
            raise ValueError('Specify either a user or a group!')

        if not isinstance(granted_by, User):
            raise ValueError('granted_by has to be a User object!')

        permission = self.is_shareable_by_user(granted_by)
        if not permission:
            raise PermissionDenied()

        share_obj = self.share_data.create(
            grant_description=grant_description,
            granted_by=granted_by,
            granted_until=granted_until,
            group=group,
            user=user,
        )
        log(
            _("{user} granted access to {shared_entity_type} '{name}' {time}").format(
                shared_entity_type=share_obj.shared_entity_type,
                name=share_obj.shared_entity_name,
                user=granted_by.username,
                time=_('until ') + share_obj.granted_until.isoformat() if share_obj.granted_until else _('permanently')
            ),
            actor=granted_by,
            category=(
                AuditLogCategoryChoices.SECRET_SUPERUSER_SHARED
                if permission == AccessPermissionTypes.SUPERUSER_ALLOWED
                else AuditLogCategoryChoices.SECRET_SHARED
            ),
            level='warning',
            reason=grant_description,
            secret=self,
        )

        return share_obj


class SecretRevision(HashIDModel):
    HASHID_NAMESPACE = "SecretRevision"

    accessed_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
    )
    created = models.DateTimeField(auto_now_add=True)
    encrypted_data = models.BinaryField()
    otp_key_set = models.BooleanField(default=False)
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
        on_delete=models.PROTECT,
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

        return now() + timedelta(hours=8) >= self.granted_until

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
