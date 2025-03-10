from base64 import b64decode
from json import dumps

from django.contrib.auth.models import Group, User
from django.db import models
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.reverse import reverse

from ..models import Secret, SecretRevision, SharedSecretData


class ContentType(models.TextChoices):
    PASSWORD = 'password', _('Password')
    CC = 'cc', _('Credit Card')
    FILE = 'file', _('File')


ACCESS_POLICY_REPR = {
    Secret.ACCESS_POLICY_ANY: "any",
    Secret.ACCESS_POLICY_HIDDEN: "hidden",
    Secret.ACCESS_POLICY_DISCOVERABLE: "discoverable",
}
REPR_ACCESS_POLICY = {v: k for k, v in ACCESS_POLICY_REPR.items()}

CONTENT_TYPE_REPR = {
    Secret.CONTENT_CC: "cc",
    Secret.CONTENT_FILE: "file",
    Secret.CONTENT_PASSWORD: "password",
}
REPR_CONTENT_TYPE = {v: k for k, v in CONTENT_TYPE_REPR.items()}

SECRET_STATUS_REPR = {
    Secret.STATUS_DELETED: "deleted",
    Secret.STATUS_NEEDS_CHANGING: "needs_changing",
    Secret.STATUS_OK: "ok",
}
SECRET_REPR_STATUS = {v: k for k, v in SECRET_STATUS_REPR.items()}

REQUIRED_CC_FIELDS = {'holder', 'expiration_month', 'expiration_year', 'number', 'security_code'}


def _extract_data(validated_data, content_type: Secret.CONTENT_CHOICES):
    data = {}
    secret_data = validated_data.get('secret_data')
    if content_type == 'password':
        for attr in ['password', 'otp_key_data']:
            if attr in secret_data:
                data[attr] = secret_data[attr]
    elif content_type == 'cc':
        for attr in ['holder', 'expiration_month', 'expiration_year', 'number', 'security_code', 'password']:
            try:
                data[attr] = secret_data[attr]
            except KeyError:
                raise serializers.ValidationError(_(f'Missing required credit card field {attr}'))
    elif content_type == 'file':
        if 'filename' in secret_data:
            data['filename'] = secret_data['filename']
        if 'file' in secret_data:
            data['file'] = b64decode(secret_data.pop('file').encode('ascii'))
        for attr in ['file', 'filename']:
            if attr in secret_data:
                data[attr] = secret_data[attr]
    return data


class SecretRevisionSerializer(serializers.HyperlinkedModelSerializer):
    api_url = serializers.HyperlinkedIdentityField(
        lookup_field='hashid',
        view_name='api.secret-revision_detail',
    )
    data_url = serializers.CharField(
        read_only=True,
        required=False,
        source='id',
    )
    set_by = serializers.SlugRelatedField(
        read_only=True,
        slug_field='username',
    )

    def to_representation(self, instance):
        rep = super(SecretRevisionSerializer, self).to_representation(instance)
        rep['data_url'] = reverse(
            'api.secret-revision_data',
            kwargs={'hashid': instance.hashid},
            request=self.context['request'],
        )
        return rep

    class Meta:
        model = SecretRevision
        fields = (
            'api_url',
            'created',
            'data_url',
            'set_by',
        )
        read_only_fields = (
            'created',
        )


class SecretSerializer(serializers.HyperlinkedModelSerializer):
    api_url = serializers.HyperlinkedIdentityField(
        lookup_field='hashid',
        view_name='api.secret_detail',
    )
    content_type = serializers.ChoiceField(
        choices=ConentType.choices,
        required=True
    )
    created_by = serializers.SlugRelatedField(
        default=serializers.CurrentUserDefault(),
        read_only=True,
        slug_field='username',
    )
    current_revision = serializers.HyperlinkedRelatedField(
        lookup_field='hashid',
        read_only=True,
        view_name='api.secret-revision_detail',
    )
    data_readable = serializers.BooleanField(
        read_only=True,
        required=False,
        source='id',
    )
    web_url = serializers.CharField(
        required=False,
        read_only=True,
    )
    secret_data = serializers.JSONField(
        required=False,
        write_only=True,
    )

    def create(self, validated_data):
        try:
            content_type = validated_data.pop('content_type')
        except KeyError:
            raise serializers.ValidationError(_(f'Missing required field content type'))
        data = _extract_data(validated_data, content_type)
        if not data:
            raise serializers.ValidationError("missing secret field (e.g. 'password')")

        instance = self.Meta.model.objects.create(**validated_data)
        instance.content_type = content_type
        instance._data = data
        instance.shared_users.add(instance.created_by)
        return instance

    def to_internal_value(self, data):
        try:
            data['access_policy'] = REPR_ACCESS_POLICY[data.get('access_policy', None)]
        except KeyError:
            # Validation will catch it
            pass

        try:
            data['status'] = SECRET_REPR_STATUS[data.get('status', None)]
        except KeyError:
            # Validation will catch it
            pass

        return super(SecretSerializer, self).to_internal_value(data)

    def to_representation(self, instance):
        rep = super(SecretSerializer, self).to_representation(instance)
        rep['access_policy'] = ACCESS_POLICY_REPR[rep['access_policy']]
        rep['content_type'] = CONTENT_TYPE_REPR[rep['content_type']]
        rep['data_readable'] = instance.is_readable_by_user(self.context['request'].user)
        rep['hashid'] = instance.hashid
        rep['status'] = SECRET_STATUS_REPR[rep['status']]
        rep['web_url'] = instance.full_url
        return rep

    def update(self, instance, validated_data):
        try:
            content_type = validated_data.pop('content_type')
        except KeyError:
            raise serializers.ValidationError(_('Missing required field content_type'))
        data = _extract_data(validated_data, content_type)
        if data:
            instance._data = data
        return instance

    def validate(self, data):
        if 'file' in data or 'filename' in data:
            if not ('file' in data and 'filename' in data):
                raise serializers.ValidationError(_('Must include both file and filename'))
        return data

    class Meta:
        model = Secret
        fields = (
            'access_policy',
            'api_url',
            'content_type',
            'created',
            'created_by',
            'current_revision',
            'data_readable',
            'description',
            'last_read',
            'name',
            'needs_changing_on_leave',
            'status',
            'url',
            'username',
            'web_url',
            'secret_data',
        )
        read_only_fields = (
            'content_type',
            'created',
            'last_read',
        )


class SharedSecretDataSerializer(serializers.ModelSerializer):
    granted_by = serializers.SlugRelatedField(
        default=serializers.CurrentUserDefault(),
        read_only=True,
        slug_field='username',
    )
    grant_description = serializers.CharField(
        allow_null=False,
    )
    granted_until = serializers.DateTimeField(
        allow_null=True,
    )
    group = serializers.SlugRelatedField(
        allow_null=True,
        queryset=Group.objects.all().order_by('name'),
        required=False,
        slug_field='name',
    )
    secret = serializers.SlugRelatedField(
        read_only=True,
        slug_field='hashid',
    )
    user = serializers.SlugRelatedField(
        allow_null=True,
        queryset=User.objects.exclude(is_active=False).order_by('username'),
        required=False,
        slug_field='username',
    )

    def validate(self, data):
        if (data['group'] and data['user']) or (not data['group'] and not data['user']):
            raise serializers.ValidationError('Choose exactly one group *or* one user to share the secret with.')

        secret = self.context['secret']
        if data['group']:
            entity_type = 'group'
            entity_name = data['group']
        else:
            entity_type = 'user'
            entity_name = data['user']

        if SharedSecretData.objects.filter(secret=secret, **{entity_type: entity_name}).exists():
            raise ValidationError(
                _(f'Secret {secret} was already shared with {entity_type} {entity_name}.').format(
                    secret=secret, entity_type=entity_type, entity_name=entity_name
                ),
                code='unique'
            )
        return data

    class Meta:
        model = SharedSecretData
        fields = ['id', 'grant_description', 'granted_on', 'granted_until', 'group', 'user', 'granted_by', 'secret']
        read_only_fields = (
            'id',
            'granted_by'
        )
