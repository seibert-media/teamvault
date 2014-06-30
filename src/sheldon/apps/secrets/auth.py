from guardian.backends import ObjectPermissionBackend as GuardianBackend

from .models import Password


class ObjectPermissionBackend(GuardianBackend):
    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active or not user_obj.is_authenticated():
            return False

        if perm == 'secrets.delete_password':
            perm = 'secrets.change_password'

        if perm in (
            'secrets.add_password',
        ):
            return True

        if isinstance(obj, Password):
            if perm == 'secrets.change_password' and obj.access_policy == Password.ACCESS_ANY:
                return True
            if perm == 'secrets.view_password':
                if obj.access_policy in (
                    Password.ACCESS_ANY,
                    Password.ACCESS_NAMEONLY,
                ) or user_obj.has_perm('secrets.change_password', obj):
                    return True

        return super(ObjectPermissionBackend, self).has_perm(
            user_obj,
            perm,
            obj=obj,
        )
