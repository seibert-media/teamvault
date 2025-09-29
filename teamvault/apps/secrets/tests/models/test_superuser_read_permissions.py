from django.contrib.auth import get_user_model
from django.test.testcases import TestCase
from django.test.utils import override_settings

from teamvault.apps.secrets.models import AccessPermissionTypes
from teamvault.apps.secrets.tests.helpers import STATIC_TEST_KEY, make_secret

User = get_user_model()

@override_settings(TEAMVAULT_SECRET_KEY=STATIC_TEST_KEY)
class TestSuperuserReadPermissions(TestCase):

    def setUp(self):
        self.superuser = User.objects.create_superuser(username="superuser")
        self.owner = User.objects.create_user(username="regular_user")
        self.secret = make_secret(self.owner)

    @override_settings(ALLOW_SUPERUSER_READS=True)
    def test_superuser_allowed_read_when_enabled(self):
        self.assertEqual(self.secret.is_readable_by_user(self.superuser), AccessPermissionTypes.SUPERUSER_ALLOWED)

    @override_settings(ALLOW_SUPERUSER_READS=False)
    def test_superuser_not_allowed_when_disabled(self):
        self.assertEqual(self.secret.is_readable_by_user(self.superuser), AccessPermissionTypes.NOT_ALLOWED)
