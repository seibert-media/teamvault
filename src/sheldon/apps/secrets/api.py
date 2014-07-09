from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import AccessRequest, Password, PasswordRevision


class AccessRequestSerializer(serializers.HyperlinkedModelSerializer):
    requester = serializers.Field(
        source='requester.username',
    )
    password = serializers.HyperlinkedRelatedField(
        view_name='api.password_detail',
    )
    reviewers = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='username',
    )
    url = serializers.HyperlinkedIdentityField(
        view_name='api.access-request_detail',
    )

    class Meta:
        model = AccessRequest
        fields = (
            'closed',
            'closed_by',
            'created',
            'password',
            'reason_request',
            'reason_rejected',
            'requester',
            'reviewers',
            'status',
            'url',
        )
        read_only_fields = (
            'closed',
            'closed_by',
            'created',
        )


class AccessRequestDetail(generics.RetrieveUpdateDestroyAPIView):
    model = AccessRequest
    serializer_class = AccessRequestSerializer

    def get_object(self):
        obj = get_object_or_404(AccessRequest, pk=self.kwargs['pk'])
        if (
            not self.request.user == obj.requester and
            not self.request.user in obj.reviewers and
            not self.request.user.is_superuser
        ):
            self.permission_denied(self.request)
        return obj

    def pre_save(self, obj):
        previous_state = AccessRequest.objects.get(pk=obj.pk)
        if (
            previous_state.status != AccessRequest.STATUS_PENDING or
            obj.status == AccessRequest.STATUS_PENDING or
            self.request.user not in previous_state.reviewers.all() or
            obj.password != previous_state.password
        ):
            self.permission_denied(self.request)

    def post_save(self, obj, created=False):
        #obj.handle_status() TODO
        pass


class AccessRequestList(generics.ListCreateAPIView):
    model = AccessRequest
    paginate_by = 50
    serializer_class = AccessRequestSerializer

    def get_queryset(self):
        return AccessRequest.get_all_readable_by_user(self.request.user)

    def pre_save(self, obj):
        obj.reason_rejected = ""
        obj.requester = self.request.user
        obj.status = AccessRequest.STATUS_PENDING

    def post_save(self, obj, created=False):
        obj.reviewers.add(self.request.user) # TODO


class PasswordRevisionSerializer(serializers.HyperlinkedModelSerializer):
    created_by = serializers.Field(
        source='set_by.username',
    )
    secret_url = serializers.CharField(
        read_only=True,
        required=False,
        source='id',
    )
    url = serializers.HyperlinkedIdentityField(
        view_name='api.password-revision_detail',
    )

    def transform_secret_url(self, obj, value):
        return reverse(
            'api.password-revision_secret',
            kwargs={'pk': obj.pk},
            request=self.context['request'],
        )

    class Meta:
        model = PasswordRevision
        fields = (
            'created',
            'created_by',
            'secret_url',
            'url',
        )
        read_only_fields = (
            'created',
        )


class PasswordSerializer(serializers.HyperlinkedModelSerializer):
    allowed_groups = serializers.SlugRelatedField(
        many=True,
        slug_field='name',
    )
    allowed_users = serializers.SlugRelatedField(
        many=True,
        slug_field='username',
    )
    created_by = serializers.Field(
        source='created_by.username',
    )
    current_revision = serializers.HyperlinkedRelatedField(
        read_only=True,
        view_name='api.password-revision_detail',
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
    )

    def transform_secret_readable(self, obj, value):
        return obj.is_readable_by_user(self.context['request'].user)

    def transform_secret_url(self, obj, value):
        if not obj.current_revision:
            # password has not been set yet
            return None
        return reverse(
            'api.password-revision_secret',
            kwargs={'pk': obj.current_revision.pk},
            request=self.context['request'],
        )

    class Meta:
        model = Password
        fields = (
            'access_policy',
            'allowed_users',
            'allowed_groups',
            'created',
            'created_by',
            'current_revision',
            'description',
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



class PasswordDetail(generics.RetrieveUpdateDestroyAPIView):
    model = Password
    serializer_class = PasswordSerializer

    def get_object(self):
        obj = get_object_or_404(Password, pk=self.kwargs['pk'])
        if not obj.is_visible_to_user(self.request.user):
            self.permission_denied(self.request)
        return obj

    def post_save(self, obj, created=False):
        if hasattr(obj, 'password'):
            obj.set_password(self.request.user, obj.password)


class PasswordList(generics.ListCreateAPIView):
    model = Password
    paginate_by = 50
    serializer_class = PasswordSerializer

    def get_queryset(self):
        return Password.get_all_visible_to_user(self.request.user)

    def pre_save(self, obj):
        obj.created_by = self.request.user

    def post_save(self, obj, created=False):
        obj.allowed_users.add(self.request.user)
        if hasattr(obj, 'password'):
            obj.set_password(self.request.user, obj.password)


class PasswordRevisionDetail(generics.RetrieveAPIView):
    model = PasswordRevision
    serializer_class = PasswordRevisionSerializer

    def get_object(self):
        obj = get_object_or_404(PasswordRevision, pk=self.kwargs['pk'])
        if not obj.password.is_readable_by_user(self.request.user):
            self.permission_denied(self.request)
        return obj


@api_view(['GET'])
def secret_get(request, pk):
    obj = get_object_or_404(PasswordRevision, pk=pk)
    if not obj.password.is_readable_by_user(request.user):
        raise PermissionDenied()
    return Response({'password': obj.password.get_password(request.user)})
