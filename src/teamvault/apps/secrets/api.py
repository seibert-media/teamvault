from base64 import decodestring, encodestring
from json import dumps, loads

from django.contrib.auth.models import Group, User
from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework import serializers
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.reverse import reverse

from .models import AccessRequest, Secret, SecretRevision


ACCESS_POLICY_REPR = {
    Secret.ACCESS_POLICY_ANY: "any",
    Secret.ACCESS_POLICY_HIDDEN: "hidden",
    Secret.ACCESS_POLICY_REQUEST: "request",
}
REPR_ACCESS_POLICY = {v: k for k, v in ACCESS_POLICY_REPR.items()}

CONTENT_TYPE_REPR = {
    Secret.CONTENT_CC: "cc",
    Secret.CONTENT_FILE: "file",
    Secret.CONTENT_PASSWORD: "password",
}
REPR_CONTENT_TYPE = {v: k for k, v in CONTENT_TYPE_REPR.items()}

STATUS_REPR = {
    Secret.STATUS_DELETED: "deleted",
    Secret.STATUS_NEEDS_CHANGING: "needs_changing",
    Secret.STATUS_OK: "ok",
}
REPR_STATUS = {v: k for k, v in STATUS_REPR.items()}

REQUIRED_CC_FIELDS = set((
    'holder', 'expiration_month', 'expiration_year', 'number', 'security_code',
))


def _extract_data(validated_data):
    if 'password' in validated_data and not \
            REQUIRED_CC_FIELDS.intersection(set(validated_data.keys())):
        return (
            validated_data.pop('password'),
            Secret.CONTENT_PASSWORD,
        )
    elif 'file' in validated_data:
        return (
            decodestring(validated_data.pop('file').encode('ascii')),
            Secret.CONTENT_FILE,
        )
    elif REQUIRED_CC_FIELDS.intersection(set(validated_data.keys())):
        data = {}
        for cc_field in REQUIRED_CC_FIELDS:
            try:
                data[cc_field] = str(validated_data.pop(cc_field))
            except KeyError:
                raise serializers.ValidationError(
                    "missing required CC field '{}'".format(cc_field)
                )
        if 'password' in validated_data:
            data['password'] = validated_data.pop('password')
        else:
            data['password'] = ""
        return (
            dumps(data),
            Secret.CONTENT_CC,
        )
    else:
        return (None, None)


class AccessRequestSerializer(serializers.HyperlinkedModelSerializer):
    api_url = serializers.HyperlinkedIdentityField(
        view_name='api.access-request_detail',
    )
    requester = serializers.Field(
        source='requester.username',
    )
    secret = serializers.HyperlinkedRelatedField(
        lookup_field='hashid',
        queryset=Secret.objects.exclude(status=Secret.STATUS_DELETED),
        view_name='api.secret_detail',
    )
    reviewers = serializers.SlugRelatedField(
        many=True,
        queryset=User.objects.exclude(is_active=False),
        slug_field='username',
    )

    class Meta:
        model = AccessRequest
        fields = (
            'api_url',
            'closed',
            'closed_by',
            'created',
            'secret',
            'reason_request',
            'reason_rejected',
            'requester',
            'reviewers',
            'status',
        )
        read_only_fields = (
            'closed',
            'closed_by',
            'created',
        )


class AccessRequestDetail(generics.RetrieveUpdateAPIView):
    model = AccessRequest
    serializer_class = AccessRequestSerializer

    def get_object(self):
        obj = get_object_or_404(AccessRequest, hashid=self.kwargs['hashid'])
        if (
            self.request.user != obj.requester and
            self.request.user not in obj.reviewers and
            not self.request.user.is_superuser
        ):
            self.permission_denied(self.request)
        return obj

    def pre_save(self, obj):
        previous_state = AccessRequest.objects.get(hashid=obj.hashid)
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
        if created:
            obj.assign_reviewers()


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
    allowed_groups = serializers.SlugRelatedField(
        many=True,
        queryset=Group.objects.all(),
        required=False,
        slug_field='name',
    )
    allowed_users = serializers.SlugRelatedField(
        many=True,
        queryset=User.objects.exclude(is_active=False),
        required=False,
        slug_field='username',
    )
    api_url = serializers.HyperlinkedIdentityField(
        lookup_field='hashid',
        view_name='api.secret_detail',
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
    expiration_month = serializers.CharField(
        required=False,
        write_only=True,
    )
    expiration_year = serializers.CharField(
        required=False,
        write_only=True,
    )
    file = serializers.CharField(
        required=False,
        write_only=True,
    )
    holder = serializers.CharField(
        required=False,
        write_only=True,
    )
    number = serializers.CharField(
        required=False,
        write_only=True,
    )
    password = serializers.CharField(
        required=False,
        write_only=True,
    )
    security_code = serializers.CharField(
        required=False,
        write_only=True,
    )

    def create(self, validated_data):
        allowed_groups = validated_data.pop('allowed_groups', [])
        allowed_users = validated_data.pop('allowed_users', [])

        data, content_type = _extract_data(validated_data)
        if not data:
            raise serializers.ValidationError("missing secret field (e.g. 'password')")

        instance = self.Meta.model.objects.create(**validated_data)

        instance.allowed_groups = allowed_groups
        instance.allowed_users = allowed_users
        instance.content_type = content_type
        instance._data = data
        return instance

    def to_internal_value(self, data):
        try:
            data['access_policy'] = REPR_ACCESS_POLICY[data.get('access_policy', None)]
        except KeyError:
            # Validation will catch it
            pass

        try:
            data['status'] = REPR_STATUS[data.get('status', None)]
        except KeyError:
            # Validation will catch it
            pass

        return super(SecretSerializer, self).to_internal_value(data)

    def to_representation(self, instance):
        rep = super(SecretSerializer, self).to_representation(instance)
        rep['access_policy'] = ACCESS_POLICY_REPR[rep['access_policy']]
        rep['content_type'] = CONTENT_TYPE_REPR[rep['content_type']]
        rep['data_readable'] = instance.is_readable_by_user(self.context['request'].user)
        rep['status'] = STATUS_REPR[rep['status']]
        return rep

    def update(self, instance, validated_data):
        data, content_type = _extract_data(validated_data)
        if content_type and content_type != instance.content_type:
            raise serializers.ValidationError("wrong secret content type")
        if data:
            instance._data = data
        return instance

    def validate(self, data):
        if 'file' in data or 'filename' in data:
            if not ('file' in data and 'filename' in data):
                raise serializers.ValidationError("must include both file and filename")
        return data

    class Meta:
        model = Secret
        fields = (
            'access_policy',
            'allowed_groups',
            'allowed_users',
            'api_url',
            'content_type',
            'created',
            'created_by',
            'current_revision',
            'data_readable',
            'description',
            'expiration_month',
            'expiration_year',
            'file',
            'filename',
            'holder',
            'last_read',
            'name',
            'needs_changing_on_leave',
            'number',
            'password',
            'security_code',
            'status',
            'url',
            'username',
        )
        read_only_fields = (
            'content_type',
            'created',
            'last_read',
        )


class SecretDetail(generics.RetrieveUpdateDestroyAPIView):
    model = Secret
    serializer_class = SecretSerializer

    def destroy(self, request, *args, **kwargs):
        obj = self.get_object()
        self.pre_delete(obj)
        obj.status = Secret.STATUS_DELETED
        obj.save()
        self.post_delete(obj)
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
    paginate_by = 25
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
        instance = serializer.save()
        if hasattr(instance, '_data'):
            instance.set_data(self.request.user, instance._data)
            del instance._data


class SecretRevisionDetail(generics.RetrieveAPIView):
    model = SecretRevision
    serializer_class = SecretRevisionSerializer

    def get_object(self):
        obj = get_object_or_404(SecretRevision, hashid=self.kwargs['hashid'])
        obj.secret.check_access(self.request.user)
        return obj


@api_view(['GET'])
def data_get(request, hashid):
    secret_revision = get_object_or_404(SecretRevision, hashid=hashid)
    secret_revision.secret.check_access(request.user)
    data = secret_revision.secret.get_data(request.user)
    if secret_revision.secret.content_type == Secret.CONTENT_PASSWORD:
        return Response({'password': data})
    elif secret_revision.secret.content_type == Secret.CONTENT_FILE:
        return Response({'file': encodestring(data).decode('ascii')})
    elif secret_revision.secret.content_type == Secret.CONTENT_CC:
        return Response(loads(data))
