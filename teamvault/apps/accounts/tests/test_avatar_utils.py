from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase

from teamvault.apps.accounts.models import UserProfile
from teamvault.apps.accounts.utils import HTTP_TIMEOUT, save_google_avatar, save_gravatar

User = get_user_model()


class TestAvatarUtils(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', email='alice@example.com')

    @mock.patch('teamvault.apps.accounts.utils.requests.get')
    def test_save_gravatar_passes_timeout_and_stores_avatar(self, mock_get):
        mock_get.return_value.ok = True
        mock_get.return_value.content = b'avatar-bytes'

        save_gravatar(self.user)

        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args.kwargs['timeout'], HTTP_TIMEOUT)
        profile = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(profile.avatar)

    @mock.patch('teamvault.apps.accounts.utils.requests.get')
    def test_save_gravatar_absorbs_request_exception(self, mock_get):
        mock_get.side_effect = requests.Timeout

        # Must not raise, otherwise a slow/unresponsive Gravatar upstream would
        # break the social-auth pipeline.
        save_gravatar(self.user)

        self.assertEqual(UserProfile.objects.filter(user=self.user).count(), 0)

    @mock.patch('teamvault.apps.accounts.utils.requests.get')
    def test_save_google_avatar_passes_timeout(self, mock_get):
        mock_get.return_value.ok = True
        mock_get.return_value.content = b'avatar-bytes'

        save_google_avatar({'picture': 'https://example.com/pic.jpg'}, self.user)

        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args.kwargs['timeout'], HTTP_TIMEOUT)
        profile = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(profile.avatar)