from collections import OrderedDict
from datetime import timedelta
from hashlib import sha256
from operator import itemgetter
from random import sample

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import Group, User
from django.contrib.postgres.search import SearchVector, SearchVectorField
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.urlresolvers import reverse
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.http import Http404
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _
from hashids import Hashids

from ...utils import send_mail
from ..audit.auditlog import log
from ..audit.models import LogEntry
from .exceptions import PermissionError


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
            # We cannot use the same salt for every model because
            # 1. sequentially create lots of secrets
            # 2. note the hashid of each secrets
            # 3. you can now enumerate access requests by using the same
            #    hashids
            # it's not a huge deal, but let's avoid it anyway
            hasher = Hashids(
                min_length=settings.HASHID_MIN_LENGTH,
                salt=self.HASHID_NAMESPACE + settings.HASHID_SALT,
            )
            self.hashid = hasher.encode(self.pk)
        # we cannot force insert anymore because we might already have
        # created the object
        kwargs['force_insert'] = False
        return super(HashIDModel, self).save(*args, **kwargs)


class AccessRequest(HashIDModel):
    HASHID_NAMESPACE = "AccessRequest"

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
        blank=True,
        null=True,
        related_name='access_requests_closed',
    )
    created = models.DateTimeField(auto_now_add=True)
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
    secret = models.ForeignKey(
        'Secret',
        related_name='access_requests',
    )
    status = models.PositiveSmallIntegerField(
        choices=STATUS_CHOICES,
        default=STATUS_PENDING,
    )

    class Meta:
        ordering = ('-created',)

    def __repr__(self):
        return "<AccessRequest {user}@'{name}' ({id})>".format(
            id=self.hashid,
            name=self.secret.name,
            user=self.requester,
        )

    @classmethod
    def get_all_readable_by_user(cls, user):
        if user.is_superuser:
            return cls.objects.all()
        return (
            cls.objects.filter(requester=user) |
            cls.objects.filter(reviewers=user)
        )

    def approve(self, reviewer):
        if self.status != self.STATUS_PENDING:
            raise PermissionDenied(_("Can't approve closed access request"))

        # make sure user is still allowed to handle secret, privileges might
        # have been revoked since the access request was made
        self.secret.check_access(reviewer)

        log(
            _("{reviewer} has approved access request #{access_request} for {requester}, "
              "allowing access to '{secret}'").format(
                access_request=self.id,
                requester=self.requester,
                reviewer=reviewer,
                secret=self.secret.name,
            ),
            actor=reviewer,
            secret=self.secret,
            user=self.requester,
        )

        self.closed = now()
        self.closed_by = reviewer
        self.status = self.STATUS_APPROVED
        self.save()

        self.secret.allowed_users.add(self.requester)

        other_reviewers = list(self.reviewers.all())
        try:
            other_reviewers.remove(reviewer)
        except ValueError:
            # review by other superuser
            pass

        send_mail(
            other_reviewers + [self.requester],
            _("[TeamVault] Access request for '{}' approved").format(self.secret.name),
            "secrets/mail_access_request_approved",
            context={
                'approved_by': reviewer.username,
                'base_url': settings.BASE_URL,
                'secret_name': self.secret.name,
                'secret_url': self.secret.get_absolute_url(),
                'username': self.requester.username,
            },
            user_from=reviewer,
        )

    def assign_reviewers(self):
        candidates = list(
            self.secret.owner_users.order_by('-last_login').filter(is_active=True)[:10]
        )
        for group in self.secret.owner_groups.all():
            candidates += list(group.user_set.order_by('-last_login').filter(is_active=True)[:3])
        if len(candidates) < 3:
            candidates += list(
                self.secret.allowed_users.order_by('-last_login').filter(is_active=True)[:10]
            )
            for group in self.secret.allowed_groups.all():
                candidates += list(group.user_set.order_by('-last_login').filter(is_active=True)[:3])
        if len(candidates) < 3:
            candidates += list(User.objects.filter(
                is_active=True,
                is_superuser=True,
            ).order_by('-last_login')[:3])
        candidates = set(candidates)
        selected = sample(candidates, min(3, len(candidates)))
        if not selected:
            raise RuntimeError(_("unable to find reviewers for {}").format(self))
        self.reviewers = selected

        send_mail(
            self.reviewers.all(),
            _("[TeamVault] Review access request for '{}'").format(self.secret.name),
            "secrets/mail_access_request_review",
            context={
                'access_request_url': reverse(
                    'secrets.access_request-detail',
                    kwargs={'hashid': self.hashid},
                ),
                'base_url': settings.BASE_URL,
                'secret_name': self.secret.name,
                'secret_url': self.secret.get_absolute_url(),
                'username': self.requester.username,
            },
            user_from=self.requester,
        )

    def reject(self, reviewer, reason=None):
        if self.status != self.STATUS_PENDING:
            raise PermissionDenied(_("Can't reject closed access request"))

        # make sure user is still allowed to handle secret, privileges might
        # have been revoked since the access request was made
        self.secret.check_access(reviewer)

        log(
            _("{reviewer} has rejected access request #{access_request} for {requester}, "
              "NOT allowing access to '{secret}'").format(
                access_request=self.id,
                requester=self.requester,
                reviewer=reviewer,
                secret=self.secret.name,
            ),
            actor=reviewer,
            secret=self.secret,
            user=self.requester,
        )

        self.closed = now()
        self.closed_by = reviewer
        self.reason_rejected = reason
        self.status = self.STATUS_REJECTED
        self.save()

        other_reviewers = list(self.reviewers.all())
        try:
            other_reviewers.remove(reviewer)
        except ValueError:
            # review by other superuser
            pass

        send_mail(
            other_reviewers + [self.requester],
            _("[TeamVault] Access request for '{}' denied").format(self.secret.name),
            "secrets/mail_access_request_denied",
            context={
                'base_url': settings.BASE_URL,
                'denied_by': reviewer.username,
                'reason': reason,
                'secret_name': self.secret.name,
                'secret_url': self.secret.get_absolute_url(),
                'username': self.requester.username,
            },
            user_from=reviewer,
        )

    def get_absolute_url(self):
        return reverse('secrets.access_request-detail', args=[str(self.hashid)])

    def is_readable_by_user(self, user):
        return (
            user == self.requester or
            user in self.reviewers.all() or
            user.is_superuser
        )


class Secret(HashIDModel):
    HASHID_NAMESPACE = "Secret"

    ACCESS_POLICY_REQUEST = 1
    ACCESS_POLICY_ANY = 2
    ACCESS_POLICY_HIDDEN = 3
    ACCESS_POLICY_CHOICES = (
        (ACCESS_POLICY_REQUEST, _("request")),
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
        default=ACCESS_POLICY_REQUEST,
    )
    allowed_groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name='allowed_passwords',
    )
    allowed_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='allowed_passwords',
    )
    content_type = models.PositiveSmallIntegerField(
        choices=CONTENT_CHOICES,
        default=CONTENT_PASSWORD,
    )
    created = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='passwords_created',
    )
    current_revision = models.ForeignKey(
        'SecretRevision',
        blank=True,
        null=True,
        related_name='_password_current_revision',
    )
    description = models.TextField(
        blank=True,
        null=True,
    )
    filename = models.CharField(
        blank=True,
        max_length=255,
        null=True,
    )
    last_read = models.DateTimeField(
        default=now,
    )
    name = models.CharField(max_length=92)
    needs_changing_on_leave = models.BooleanField(
        default=True,
    )
    owner_groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name='owned_passwords',
    )
    owner_users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name='owned_passwords',
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
        elif not self.is_readable_by_user(user):
            raise PermissionDenied()

    def get_absolute_url(self):
        return reverse('secrets.secret-detail', args=[str(self.hashid)])

    def get_data(self, user):
        if not self.current_revision:
            raise Http404
        if not self.is_readable_by_user(user):
            log(_(
                    "{user} tried to access '{name}' without permission"
                ).format(
                    name=self.name,
                    user=user.username,
                ),
                actor=user,
                level='warn',
                secret=self,
            )
            raise PermissionError(_(
                "{user} not allowed access to '{name}' ({id})"
            ).format(
                id=self.id,
                name=self.name,
                user=user.username,
            ))
        f = Fernet(settings.TEAMVAULT_SECRET_KEY)
        log(_(
                "{user} read '{name}'"
            ).format(
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

        plaintext_data = f.decrypt(self.current_revision.encrypted_data.tobytes())
        if self.content_type != Secret.CONTENT_FILE:
            plaintext_data = plaintext_data.decode('utf-8')
        return plaintext_data

    @classmethod
    def get_all_readable_by_user(cls, user):
        if user.is_superuser:
            return cls.objects.all()
        return (
            cls.objects.filter(access_policy=cls.ACCESS_POLICY_ANY) |
            cls.objects.filter(allowed_users=user) |
            cls.objects.filter(allowed_groups__in=user.groups.all())
        ).exclude(status=cls.STATUS_DELETED).distinct()

    @classmethod
    def get_all_visible_to_user(cls, user, queryset=None):
        if queryset is None:
            queryset = cls.objects.all()
        if user.is_superuser:
            return queryset
        return (
            queryset.filter(access_policy__in=(cls.ACCESS_POLICY_ANY, cls.ACCESS_POLICY_REQUEST)) |
            queryset.filter(allowed_users=user) |
            queryset.filter(allowed_groups__in=user.groups.all())
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
        result = list(OrderedDict.fromkeys(
            list(name_hits) + list(fulltext_hits) + list(substr_hits)
        ))
        if limit:
            return result[:limit]
        else:
            return result

    def is_readable_by_user(self, user):
        return (
            user.is_superuser or (
                (
                    self.access_policy == self.ACCESS_POLICY_ANY or
                    user in self.allowed_users.all() or
                    set(self.allowed_groups.all()).intersection(set(user.groups.all()))
                ) and self.status != self.STATUS_DELETED
            )
        )

    def is_visible_to_user(self, user):
        return (
            user.is_superuser or (
                (
                    self.access_policy in (self.ACCESS_POLICY_ANY, self.ACCESS_POLICY_REQUEST) or
                    self.is_readable_by_user(user)
                ) and self.status != self.STATUS_DELETED
            )
       )

    def set_data(self, user, plaintext_data):
        if not self.is_readable_by_user(user):
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
        f = Fernet(settings.TEAMVAULT_SECRET_KEY)
        encrypted_data = f.encrypt(plaintext_data)
        try:
            # see the comment on unique_together for SecretRevision
            p = SecretRevision.objects.get(
                encrypted_data=encrypted_data,
                secret=self,
            )
        except SecretRevision.DoesNotExist:
            p = SecretRevision()
        p.encrypted_data = encrypted_data
        # the hash is needed for unique_together (see below)
        # unique_together uses an index on its fields which is
        # problematic with the largeish blobs we might store here (see
        # issue #30)
        p.encrypted_data_sha256 = sha256(encrypted_data).hexdigest()
        p.length = plaintext_length
        p.secret = self
        p.set_by = user
        p.save()
        p.accessed_by.add(user)
        if self.current_revision:
            previous_revision_id = self.current_revision.id
        else:
            previous_revision_id = _("none")
        self.current_revision = p
        self.last_read = now()
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


class SecretRevision(HashIDModel):
    HASHID_NAMESPACE = "SecretRevision"

    accessed_by = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
    )
    created = models.DateTimeField(auto_now_add=True)
    encrypted_data = models.BinaryField()
    encrypted_data_sha256 = models.CharField(
        max_length=64,
    )
    length = models.PositiveIntegerField(
        default=0,
    )
    secret = models.ForeignKey(
        Secret,
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
        # employee leaves, password 3 is correctly assumed known to
        # the employee.
        unique_together = (('encrypted_data_sha256', 'secret'),)

    def __repr__(self):
        return "<SecretRevision '{name}' ({id})>".format(id=self.hashid, name=self.secret.name)


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
