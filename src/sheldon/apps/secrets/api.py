from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm
from rest_framework import generics
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import Password


class PasswordSerializer(serializers.HyperlinkedModelSerializer):
    created_by = serializers.Field(
        source='created_by.username',
    )
    id_token = serializers.CharField(
        read_only=True,
        required=False,
        source='id_token',
    )
    password = serializers.CharField(
        required=False,
        write_only=True,
    )
    secret_readable = serializers.BooleanField(
        read_only=True,
        required=False,
        source='id',
    )
    secret_url = serializers.CharField(
        read_only=True,
        required=False,
        source='id',
    )
    url = serializers.HyperlinkedIdentityField(
        view_name='api.password_detail',
        lookup_field='id_token',
    )

    def transform_secret_readable(self, obj, value):
        return self.context['request'].user.has_perm('secrets.change_password', obj)

    def transform_secret_url(self, obj, value):
        return reverse(
            'api.password_secret',
            kwargs={'id_token': obj.id_token},
            request=self.context['request'],
        )

    class Meta:
        model = Password
        fields = (
            'access_policy',
            'created',
            'created_by',
            'description',
            'id_token',
            'last_read',
            'name',
            'needs_changing_on_leave',
            'password',
            'secret_readable',
            'secret_url',
            'status',
            'url',
            'username',
        )
        read_only_fields = (
            'created',
            'last_read',
        )

    def pre_save(self, obj):
        if not obj.created_by:
            obj.created_by = self.context['request'].user

    def post_save(self, obj, created=False):
        if created:
            assign_perm('secrets.change_password', self.context['request'].user, obj)


class PasswordDetail(generics.RetrieveUpdateDestroyAPIView):
    model = Password
    serializer_class = PasswordSerializer

    def get_object(self):
        obj = get_object_or_404(Password, id_token=self.kwargs['id_token'])
        if not self.request.user.has_perm('secrets.view_password', obj):
            self.permission_denied(self.request)
        return obj


class PasswordList(generics.ListCreateAPIView):
    model = Password
    paginate_by = 50
    serializer_class = PasswordSerializer

    def get_queryset(self):
        return Password.get_all_visible_to_user(self.request.user)


class PasswordSecret(viewsets.ViewSet):
    def retrieve(self, request, id_token=None):
        obj = get_object_or_404(Password, id_token=id_token)
        if not request.user.has_perm('secrets.change_password', obj):
            self.permission_denied(request)
        return Response({'password': obj.get_password(request.user)})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def secret_get(request, id_token):
    obj = get_object_or_404(Password, id_token=id_token)
    if not request.user.has_perm('secrets.change_password', obj):
        raise PermissionDenied()
    return Response({'password': obj.get_password(request.user)})
