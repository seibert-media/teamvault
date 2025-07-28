import base64
from datetime import timedelta
from hashlib import sha256
from json import JSONDecodeError, dumps, loads
from operator import itemgetter
from dataclasses import dataclass

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import models, transaction
from django.db.models import BooleanField, Case, Max, Q, Value, When
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import Http404
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from hashids import Hashids
from pyotp import TOTP
import typing as t

from teamvault.apps.secrets.enums import AccessPolicy, ContentType, SecretStatus
from teamvault.apps.secrets.utils import copy_meta_from_secret, meta_changed

from .exceptions import PermissionError
from ..audit.auditlog import log
from ..audit.models import AuditLogCategoryChoices, LogEntry


class AccessPermissionTypes(models.IntegerChoices):
    NOT_ALLOWED = 0
    ALLOWED = 1
    TEMPORARILY_ALLOWED = 2
    SUPERUSER_ALLOWED = 3


def validate_url(value):
    if '://' not in value or value.startswith('javascript:') or value.startswith('data:'):
        raise ValidationError(_('invalid URL'))


def log_secret_read(
    *,
    readable: AccessPermissionTypes,
    secret,
    secret_revision,
    user,
):
    """
    Centralised audit-logging + permission handling for `get_data`.

    Raises PermissionError on denied access
    """
    if not readable:
        log(
            _("{user} tried to access '{name}' without permission").format(name=secret.name, user=user.username),
            actor=user,
            category=AuditLogCategoryChoices.SECRET_PERMISSION_VIOLATION,
            level='warning',
            secret=secret,
        )
        raise PermissionError(
            _("{user} not allowed access to '{name}' ({id})").format(
                id=secret.id,
                name=secret.name,
                user=user.username,
            )
        )

    # Decide which success category applies
    if readable == AccessPermissionTypes.SUPERUSER_ALLOWED:
        category = AuditLogCategoryChoices.SECRET_ELEVATED_SUPERUSER_READ
        msg_tpl = _("{user} used superuser privileges to read '{name}'")
    else:
        category = AuditLogCategoryChoices.SECRET_READ
        msg_tpl = _("{user} read '{name}'")

    # Write the success log entry
    log(
        msg_tpl.format(name=secret.name, user=user.username),
        actor=user,
        category=category,
        level='info',
        secret=secret,
        secret_revision=secret_revision,
    )


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
    HASHID_NAMESPACE = 'Secret'

    access_policy = models.PositiveSmallIntegerField(
        choices=AccessPolicy,
        default=AccessPolicy.DISCOVERABLE,
    )
    content_type = models.PositiveSmallIntegerField(
        choices=ContentType,
        default=ContentType.PASSWORD,
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
        choices=SecretStatus,
        default=SecretStatus.OK,
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

    def permission_checker(self, user):
        shares = self.share_data.for_user(user)
        return PermissionChecker(
            user=user,
            secret=self,
            shares=shares
        )

    def check_read_access(self, user):
        permissions = self.permission_checker(user)
        if not permissions.is_visible():
            raise Http404

        readable = permissions.is_readable()
        if not readable:
            raise PermissionDenied()
        return readable

    def check_share_access(self, user):
        permissions = self.permission_checker(user)
        if not permissions.is_visible():
            raise Http404

        if not permissions.is_shareable():
            raise PermissionDenied()
        return permissions.is_shareable()

    @property
    def full_url(self):
        return settings.BASE_URL.rstrip('/') + self.get_absolute_url()

    def get_absolute_url(self):
        return reverse('secrets.secret-detail', args=[str(self.hashid)])

    def get_data(self, user):
        if not self.current_revision:
            raise Http404

        readable = self.permission_checker(user).is_readable()
        log_secret_read(
            readable=readable,
            secret=self,
            secret_revision=self.current_revision,
            user=user,
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
            if self.content_type == ContentType.FILE:
                plaintext_data = base64.b64decode(plaintext_data['file_content'])
        except JSONDecodeError:
            if self.content_type == ContentType.PASSWORD:
                plaintext_data = dict(password=plaintext_data)

        return plaintext_data

    def get_otp(self, request):
        cached_otp_session_key = f'otp_key_data-{self.hashid}-{self.current_revision_id}'
        if request.session.get(cached_otp_session_key):
            data = request.session[cached_otp_session_key]
        else:
            data = self.get_data(request.user)
            request.session['otp_key_data'] = {
                'otp_key': data['otp_key'],
                'digits': int(data.get('digits', 6)),
            }
        otp_key = data['otp_key']
        digits = int(data.get('digits', 6))
        totp = TOTP(otp_key, digits=digits)
        return totp.now()

    @classmethod
    def get_all_readable_by_user(cls, user):
        if user.is_superuser and settings.ALLOW_SUPERUSER_READS:
            return cls.objects.all()

        allowed_shares = (
            SharedSecretData.objects.for_user(user)
            .values('secret__pk')
        )
        return (
            cls.objects.filter(Q(access_policy=AccessPolicy.ANY) | Q(pk__in=allowed_shares))
            .exclude(status=SecretStatus.DELETED)
            .distinct()
        )

    @classmethod
    def get_all_visible_to_user(cls, user, queryset=None):
        if queryset is None:
            queryset = cls.objects.all()

        if user.is_superuser:
            return queryset

        allowed_shares = (
            SharedSecretData.objects.with_expiry_state()
            .filter(Q(user=user) | Q(group__user=user))
            .exclude(is_expired=True)
            .values('secret__pk')
        )
        return (
            queryset.filter(
                Q(
                    access_policy__in=(
                        AccessPolicy.ANY,
                        AccessPolicy.DISCOVERABLE,
                    )
                )
                | Q(pk__in=allowed_shares)
            )
            .exclude(status=SecretStatus.DELETED)
            .distinct()
        )

    @classmethod
    def get_most_used_for_user(cls, user, limit=5):
        since = now() - timedelta(days=90)
        accessed_secrets = (
            LogEntry.objects.filter(
                actor=user,
                secret__isnull=False,
                time__gte=since,
            )
            .order_by('secret')
            .values('secret')
            .annotate(
                access_count=models.Count('secret'),
            )
        )
        ordered_secrets = sorted(accessed_secrets, key=itemgetter('access_count'), reverse=True)
        return [cls.objects.get(id=item['secret']) for item in ordered_secrets[:limit]]

    @classmethod
    def get_most_recently_used_for_user(cls, user, limit=5):
        log_entries = (
            LogEntry.objects.filter(actor=user)
            .values('secret')
            .annotate(latest_time=Max('time'))
            .order_by('-latest_time')[:limit]
        )

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
                models.Q(filename__icontains=term)
                | models.Q(url__icontains=term)
                | models.Q(username__icontains=term)
                | models.Q(hashid__exact=term)
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

    def needs_changing(self):
        return self.status == SecretStatus.NEEDS_CHANGING

    def share(self, grant_description, granted_by, user=None, group=None, granted_until=None):
        if (user and group) or (not user and not group):
            raise ValueError('Specify either a user or a group!')

        if not isinstance(granted_by, User):
            raise ValueError('granted_by has to be a User object!')

        shareable = self.permission_checker(granted_by).is_shareable()
        if not shareable:
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
                time=_('until ') + share_obj.granted_until.isoformat() if share_obj.granted_until else _('permanently'),
            ),
            actor=granted_by,
            category=(
                AuditLogCategoryChoices.SECRET_SUPERUSER_SHARED
                if shareable == AccessPermissionTypes.SUPERUSER_ALLOWED
                else AuditLogCategoryChoices.SECRET_SHARED
            ),
            level='warning',
            reason=grant_description,
            secret=self,
        )

        return share_obj


class SecretRevision(HashIDModel):
    HASHID_NAMESPACE = 'SecretRevision'

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
    last_read = models.DateTimeField(auto_now=True)

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

    @classmethod
    def _create_from_secret(
        cls,
        *,
        secret: Secret,
        set_by: User,
        plaintext_data,
        skip_access_check: bool = False,
    ) -> t.Self:
        # skip_access_check is used when initially creating a secret
        # and makes it possible to create secrets you don't have access
        # to
        if not skip_access_check:
            readable = secret.permission_checker(set_by).is_readable()
            if not readable:
                raise PermissionError(
                    _("{user} not allowed access to '{name}' ({id})").format(
                        id=secret.id, name=secret.name, user=set_by.username
                    )
                )

        content_type = secret.content_type
        set_password = content_type == ContentType.PASSWORD and 'password' in plaintext_data
        set_otp = content_type == ContentType.PASSWORD and 'otp_key' in plaintext_data

        fernet = Fernet(settings.TEAMVAULT_SECRET_KEY)

        if secret.current_revision and content_type == ContentType.PASSWORD:
            old_dec = fernet.decrypt(secret.current_revision.encrypted_data).decode()
            try:
                old_data = loads(old_dec)
            except JSONDecodeError:
                old_data = {'password': old_dec}

            if not set_password:
                plaintext_data['password'] = old_data['password']
            if not set_otp and 'otp_key' in old_data:
                for k in ('otp_key', 'digits', 'algorithm'):
                    if k in old_data:
                        plaintext_data[k] = old_data[k]
                        set_otp = True

        if content_type == ContentType.PASSWORD and 'password' in plaintext_data:
            sha_src = plaintext_data['password']
        else:
            sha_src = dumps(plaintext_data)

        sha_sum = sha256(sha_src.encode('utf-8')).hexdigest()

        revision, created = cls.objects.get_or_create(
            secret=secret,
            plaintext_data_sha256=sha_sum,
            defaults={
                'otp_key_set': set_otp,
                'set_by': set_by,
            },
        )

        if not revision.latest_meta.name:
            # Hashid exists only _after_ the first save.
            revision.latest_meta.name = f'{secret.name} - {revision.hashid}'

        # save the length before encoding so multi-byte characters don't
        # mess up the result
        revision.length = (
            len(plaintext_data['password'])
            if content_type == ContentType.PASSWORD and 'password' in plaintext_data
            else len(plaintext_data)
        )
        revision.encrypted_data = fernet.encrypt(dumps(plaintext_data).encode())

        if created:
            for f in (
                "description", "username", "url", "filename",
                "access_policy", "needs_changing_on_leave", "status",
            ):
                setattr(revision, f, getattr(secret, f))

        revision.save()
        revision.accessed_by.add(set_by)

        return revision

    @classmethod
    def _create_from_revision(
        cls,
        *,
        old_revision: t.Self,
        set_by: User,
        meta_snapshot: "SecretMetaSnapshot | None" = None,
        skip_access_check: bool = False,
    ) -> t.Self:
        """Re‑use the data of an existing revision to create a new one and
        make it the secret’s current revision.

        Returns the (new or reused) revision object that is now current.
        """
        secret = old_revision.secret

        if not skip_access_check:
            readable = secret.permission_checker(set_by).is_readable()
            if not readable:
                raise PermissionError(
                    _("{user} not allowed to roll back '{name}' ({id})").format(
                        id=secret.id,
                        name=secret.name,
                        user=set_by.username,
                    )
                )

        if meta_snapshot is not None:
            snap_src = meta_snapshot
        else:
            snap_src = old_revision.latest_meta

        if snap_src is None:
            # legacy fallback: reconstruct from the Secret itself
            snapshot_kwargs = copy_meta_from_secret(secret)
            snapshot_kwargs['set_by'] = set_by
        else:
            snapshot_kwargs = {
                'description': snap_src.description,
                'username': snap_src.username,
                'url': snap_src.url,
                'filename': snap_src.filename,
                'access_policy': snap_src.access_policy,
                'needs_changing_on_leave': snap_src.needs_changing_on_leave,
                'status': snap_src.status,
                'set_by': set_by,
            }

        new_rev, created = cls.objects.get_or_create(
            secret=secret,
            plaintext_data_sha256=old_revision.plaintext_data_sha256,
            defaults={
                'encrypted_data': old_revision.encrypted_data,
                'otp_key_set': old_revision.otp_key_set,
                'length': old_revision.length,
                'set_by': set_by,
            },
        )

        new_rev.name = f'{secret.name} - {new_rev.hashid}'
        new_rev.save()

        raw = dumps(
            {k: snapshot_kwargs[k] for k in snapshot_kwargs},
            sort_keys=True,
            default=str,
        )
        wanted_hash = sha256(raw.encode()).hexdigest()

        # try to reuse an identical snapshot (same revision + hash)
        snap = SecretMetaSnapshot.objects.filter(
            revision=new_rev,
            meta_sha256=wanted_hash,
        ).first()

        # otherwise create a fresh one for this actor
        if snap is None:
            snap = SecretMetaSnapshot.objects.create(
                secret=secret,
                revision=new_rev,
                meta_sha256=wanted_hash,
               **snapshot_kwargs,
            )

        new_rev.accessed_by.add(set_by)
        return new_rev

    def permission_checker(self, user):
        """Return a PermissionChecker for either the latest metadata snapshot
        or, if no snapshot exists yet, the parent Secret itself.
        """
        meta = self.latest_meta
        shares = self.secret.share_data.for_user(user)

        return PermissionChecker(
            user=user,
            secret=self.secret,
            meta=meta,
            shares=shares
        )

    @property
    def latest_meta(self):
        """Return the newest metadata snapshot"""
        return self.meta_snaps.first()

    def get_data(self, user):
        readable = self.permission_checker(user).is_readable()
        log_secret_read(readable=readable, secret=self.secret, secret_revision=self, user=user)
        # Record that this user has now seen this specific revision's data
        self.accessed_by.add(user)
        self.last_read = now()
        self.save()

        f = Fernet(settings.TEAMVAULT_SECRET_KEY)

        plaintext_data = f.decrypt(self.encrypted_data).decode('utf-8')
        try:
            plaintext_data = loads(plaintext_data)
            if self.secret.content_type == ContentType.FILE:
                plaintext_data = base64.b64decode(plaintext_data['file_content'])
        except JSONDecodeError:
            if self.secret.content_type == ContentType.PASSWORD:
                plaintext_data = dict(password=plaintext_data)

        return plaintext_data

    def __repr__(self):
        return "<SecretRevision '{name}' ({id})>".format(id=self.hashid, name=self.secret.name)

    @property
    def is_current_revision(self):
        return self.secret.current_revision == self


class SecretMetaSnapshot(models.Model):
    """
    Immutable copy of a Secret’s metadata
    """
    secret = models.ForeignKey(
        Secret,
        on_delete=models.CASCADE,
        related_name='meta_snaps',
        # null=True,
        # blank=True,
    )
    revision = models.ForeignKey(
        'SecretRevision',
        on_delete=models.CASCADE,
        related_name='meta_snaps',
    )
    created = models.DateTimeField(auto_now_add=True)
    set_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='secret_meta_snaps'
    )

    # metadata
    description = models.TextField(blank=True, null=True)
    username = models.CharField(max_length=255, blank=True, null=True)
    url = models.CharField(max_length=255, blank=True, null=True, validators=[validate_url])
    filename = models.CharField(max_length=255, blank=True, null=True)

    # governance
    access_policy = models.PositiveSmallIntegerField(choices=AccessPolicy)
    needs_changing_on_leave = models.BooleanField()
    status = models.PositiveSmallIntegerField(choices=SecretStatus)

    # FIXME why would we want to guard against duplicates?
    # duplicate guard UNUSED!
    meta_sha256 = models.CharField(max_length=64, editable=False)

    class Meta:
        ordering = ('-created',)
        get_latest_by = 'created'
        constraints = [
            models.UniqueConstraint(
                fields=('revision', 'meta_sha256'),
                name='uniq_meta_per_revision',
            )
        ]

    def __str__(self):
        return f'MetaSnapshot {self.id} for rev {self.revision_id}'

    def save(self, *args, **kwargs):
        # Compute hash over the _meaningful_ payload (excluding PK/timestamps)
        raw = dumps(
            {
                'description': self.description,
                'username': self.username,
                'url': self.url,
                'filename': self.filename,
                'access_policy': self.access_policy,
                'needs_changing_on_leave': self.needs_changing_on_leave,
                'status': self.status,
                'set_by': self.set_by,
            },
            sort_keys=True,
            default=str,
        )
        self.meta_sha256 = sha256(raw.encode()).hexdigest()
        super().save(*args, **kwargs)


class SecretShareQuerySet(models.QuerySet):
    # TODO: Rename to group_shares, user_shares
    def groups(self):
        return self.with_expiry_state().filter(group__isnull=False).order_by('group__name')

    def users(self):
        return self.with_expiry_state().filter(user__isnull=False).order_by('user__username')

    def with_expiry_state(self):
        return self.annotate(
            is_expired=Case(
                When(granted_until__lte=now(), then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            )
        )

    def for_user(self, user: User):
        """Return non‑expired shares that apply to the user
        (direct or via group)."""
        return (
            self.with_expiry_state()
                .filter(Q(user=user) | Q(group__user=user))
                .exclude(is_expired=True)
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

    grant_description = models.TextField(null=True)

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
                    (Q(group__isnull=False) & Q(user__isnull=True)) | (Q(group__isnull=True) & Q(user__isnull=False))
                ),
                name='only_one_set',
            ),
        ]
        unique_together = [('group', 'secret'), ('user', 'secret')]


class SharedSecretDataQuerySet(models.QuerySet):
    def for_user(self, user: User):
        """Return non‑expired shares that apply to the user
        (direct or via group)."""
        return (
            self.with_expiry_state()
                .filter(Q(user=user) | Q(group__user=user))
                .exclude(is_expired=True)
        )




@receiver(post_save, sender=Secret)
def update_search_index(sender, **kwargs):
    Secret.objects.filter(id=kwargs['instance'].id).update(
        search_index=(
            SearchVector('name', weight='A')
            + SearchVector('description', weight='B')
            + SearchVector('username', weight='C')
            + SearchVector('filename', weight='D')
        ),
    )


@dataclass(frozen=True, slots=True)
class PermissionChecker:
    user: User
    secret: Secret
    shares: SecretShareQuerySet
    meta: SecretMetaSnapshot | None = None

    def _secret_deleted(self) -> bool:
        return self.secret.status == SecretStatus.DELETED

    def _superuser_override(self) -> bool:
        return self.user.is_superuser and settings.ALLOW_SUPERUSER_READS

    def _access_policy(self) -> AccessPolicy:
        if self.meta:
            return self.meta.access_policy
        return self.secret.access_policy

    def is_discoverable(self) -> bool:
        return self._access_policy() in {
            AccessPolicy.ANY,
            AccessPolicy.DISCOVERABLE,
        }

    def _has_permanent_share(self) -> bool:
        return self.shares.filter(granted_until__isnull=True).exists()

    def is_readable(self) -> AccessPermissionTypes:
        if self._secret_deleted():
            return AccessPermissionTypes.NOT_ALLOWED
        if self._superuser_override():
            return AccessPermissionTypes.SUPERUSER_ALLOWED

        if self._access_policy() == AccessPolicy.ANY or self._has_permanent_share():
            return AccessPermissionTypes.ALLOWED
        if self.shares.exists():
            return AccessPermissionTypes.TEMPORARILY_ALLOWED
        return AccessPermissionTypes.NOT_ALLOWED

    def is_shareable(self) -> AccessPermissionTypes:
        """Checks if the user can share the secret."""
        read_permission = self.is_readable()

        # Only users with permanent read access can share
        if read_permission == AccessPermissionTypes.ALLOWED:
            return AccessPermissionTypes.ALLOWED
        # NOTE this originally didn't check ALLOW_SUPERUSER_READS. On purpose?
        if self._superuser_override():
            return AccessPermissionTypes.SUPERUSER_ALLOWED

        return AccessPermissionTypes.NOT_ALLOWED

    def is_visible(self) -> AccessPermissionTypes:
        """Checks if the secret is visible to the user in lists."""
        status = self.meta.status if self.meta else self.secret.status
        if status == SecretStatus.DELETED:
            return AccessPermissionTypes.NOT_ALLOWED

        if self.is_discoverable() or self.is_readable():
            return AccessPermissionTypes.ALLOWED

        return AccessPermissionTypes.NOT_ALLOWED
