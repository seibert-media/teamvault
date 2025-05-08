from base64 import b64encode

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from rest_framework import generics
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from teamvault.apps.audit.auditlog import log
from teamvault.apps.audit.models import AuditLogCategoryChoices
from .serializers import SecretDetailSerializer, SecretRevisionSerializer, SecretSerializer, SharedSecretDataSerializer
from ..models import AccessPermissionTypes, Secret, SecretRevision, SharedSecretData
from ..utils import generate_password


class SecretDetail(generics.RetrieveUpdateDestroyAPIView):
    model = Secret
    serializer_class = SecretDetailSerializer

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        obj.status = Secret.STATUS_DELETED
        obj.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_object(self):
        obj = get_object_or_404(Secret, hashid=self.kwargs['hashid'])
        if not obj.is_visible_to_user(self.request.user):
            self.permission_denied(self.request)
        return obj

    def perform_update(self, serializer):
        instance = serializer.save()
        if hasattr(instance, '_data'):
            instance.set_data(self.request.user, instance._data)
            del instance._data


class SecretList(generics.ListCreateAPIView):
    model = Secret
    serializer_class = SecretSerializer

    def get_queryset(self):
        if 'search' in self.request.query_params:
            return Secret.get_search_results(
                self.request.user,
                self.request.query_params['search'],
            )
        else:
            return Secret.get_all_visible_to_user(self.request.user)

    def perform_create(self, serializer):
        instance = serializer.save(created_by=self.request.user)
        if hasattr(instance, '_data'):
            instance.set_data(self.request.user, instance._data, skip_access_check=True)
            del instance._data


class SecretRevisionDetail(generics.RetrieveAPIView):
    model = SecretRevision
    serializer_class = SecretRevisionSerializer

    def get_object(self):
        obj = get_object_or_404(SecretRevision, hashid=self.kwargs['hashid'])
        obj.secret.check_read_access(self.request.user)
        return obj


class SecretShare(generics.ListCreateAPIView):
    model = SharedSecretData
    serializer_class = SharedSecretDataSerializer

    def get_object(self):
        obj = get_object_or_404(Secret, hashid=self.kwargs['hashid'])
        return obj

    def get_queryset(self):
        obj = self.get_object()
        return obj.share_data.all()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['secret'] = self.get_object()
        return context

    def perform_create(self, serializer):
        secret = self.get_object()
        permission = secret.is_shareable_by_user(self.request.user)
        if not permission:
            raise PermissionDenied

        obj = serializer.save(granted_by=self.request.user, secret=secret)
        log(
            _("{user} granted access to {shared_entity_type} '{name}' {time}").format(
                shared_entity_type=obj.shared_entity_type,
                name=obj.shared_entity_name,
                user=self.request.user.username,
                time=_('until ') + obj.granted_until.isoformat() if obj.granted_until else _('permanently')
            ),
            actor=self.request.user,
            category=(
                AuditLogCategoryChoices.SECRET_SUPERUSER_SHARED
                if permission == AccessPermissionTypes.SUPERUSER_ALLOWED
                else AuditLogCategoryChoices.SECRET_SHARED
            ),
            level='warning',
            secret=secret,
        )


class SecretShareDetail(generics.RetrieveDestroyAPIView):
    model = SharedSecretData
    serializer_class = SharedSecretDataSerializer

    def get_object(self):
        obj = get_object_or_404(SharedSecretData, secret__hashid=self.kwargs['hashid'], pk=self.kwargs['pk'])
        return obj

    def perform_destroy(self, instance):
        permission = instance.secret.is_shareable_by_user(self.request.user)
        if not permission:
            raise PermissionDenied()

        secret = instance.secret
        entity_type = instance.shared_entity_type
        entity_name = instance.shared_entity_name
        instance.delete()

        log(
            _("{user} removed access of {shared_entity_type} '{name}'").format(
                shared_entity_type=entity_type,
                name=entity_name,
                user=self.request.user.username,
            ),
            actor=self.request.user,
            category=(
                AuditLogCategoryChoices.SECRET_SUPERUSER_SHARE_REMOVED
                if permission == AccessPermissionTypes.SUPERUSER_ALLOWED
                else AuditLogCategoryChoices.SECRET_SHARE_REMOVED
            ),
            level='warning',
            secret=secret,
        )


@api_view(['GET'])
def data_get(request, hashid):
    secret_revision = get_object_or_404(SecretRevision, hashid=hashid)
    secret_revision.secret.check_read_access(request.user)
    data = secret_revision.secret.get_data(request.user)
    if secret_revision.secret.content_type == Secret.CONTENT_PASSWORD:
        return Response({'password': data["password"]})
    elif secret_revision.secret.content_type == Secret.CONTENT_FILE:
        return Response({'file': b64encode(data).decode('ascii')})
    elif secret_revision.secret.content_type == Secret.CONTENT_CC:
        return Response(data)


@api_view(['GET'])
def generate_password_view(*_args, **_kwargs):
    return Response(generate_password(
        settings.PASSWORD_LENGTH,
        settings.PASSWORD_DIGITS,
        settings.PASSWORD_UPPER,
        settings.PASSWORD_LOWER,
        settings.PASSWORD_SPECIAL
    ))


@api_view(['GET'])
def otp_get(request, hashid):
    secret_revision = get_object_or_404(SecretRevision, hashid=hashid)
    secret = secret_revision.secret
    secret.check_read_access(request.user)
    otp = secret.get_otp(request)
    return Response(otp)
