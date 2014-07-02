from django.shortcuts import get_object_or_404
from guardian.shortcuts import assign_perm
from rest_framework import generics
from rest_framework import serializers

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

    def transform_secret_readable(self, obj, value):
        return self.context['request'].user.has_perm('secrets.change_password', obj)

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
            'status',
            'username',
        )
        read_only_fields = (
            'created',
            'created_by',
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
