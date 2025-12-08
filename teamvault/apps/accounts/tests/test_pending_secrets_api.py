import csv
import io

from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from teamvault.apps.secrets.models import Secret, SharedSecretData


class TestPendingSecretsEndpoints(APITestCase):
    def setUp(self):
        self.admin_user = User.objects.create_user(
            username="admin_alice", password="password", is_superuser=True, is_staff=True
        )
        self.target_user = User.objects.create_user(
            username="target_bob", password="password", is_active=True
        )

        self.secret_needs_change = Secret.objects.create(
            name="Critical DB Password",
            created_by=self.admin_user,
            access_policy=Secret.ACCESS_POLICY_HIDDEN,
            status=Secret.STATUS_NEEDS_CHANGING,
            needs_changing_on_leave=True,
        )
        self.share1 = SharedSecretData.objects.create(
            secret=self.secret_needs_change,
            user=self.target_user,
            granted_by=self.admin_user,
        )

        self.secret_ok = Secret.objects.create(
            name="Guest WiFi Password",
            created_by=self.admin_user,
            access_policy=Secret.ACCESS_POLICY_HIDDEN,
            status=Secret.STATUS_OK,
            needs_changing_on_leave=True,
        )
        SharedSecretData.objects.create(
            secret=self.secret_ok,
            user=self.target_user,
            granted_by=self.admin_user,
        )

        self.target_user.is_active = False
        self.target_user.save()

    def test_api_permission_denied_for_non_admin(self):
        """Standard users should not be able to access the API."""
        self.client.force_authenticate(user=self.target_user)
        url = reverse('accounts.api.user-pending-secrets', kwargs={'username': self.target_user.username})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_json_payload_contains_required_fields(self):
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('accounts.api.user-pending-secrets', kwargs={'username': self.target_user.username})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = response.json()

        if 'results' in data:
            results = data['results']
        else:
            results = data

        self.assertEqual(len(results), 1)
        entry = results[0]

        # Verify Fields
        self.assertEqual(entry['name'], "Critical DB Password")
        self.assertEqual(entry['hashid'], self.secret_needs_change.hashid)
        self.assertEqual(entry['status'], "needs changing")
        self.assertIn('http', entry['web_url'])  # Ensure it's a full URL
        self.assertIsNotNone(entry['last_shared'])
        self.assertIsNotNone(entry['last_changed'])

    def test_csv_rows_match_data(self):
        """Test the CSV Export View."""
        self.client.force_login(user=self.admin_user)
        url = reverse('accounts.user-pending-secrets-csv', kwargs={'username': self.target_user.username})

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn(f'attachment; filename="{self.target_user.username}_pending_secrets.csv"',
                      response['Content-Disposition'])

        content = response.content.decode('utf-8')
        csv_reader = csv.reader(io.StringIO(content))
        rows = list(csv_reader)

        expected_header = ['Name', 'HashID', 'Type', 'URL', 'Status', 'Last Changed', 'Last Read', 'Last Shared']
        self.assertEqual(rows[0], expected_header)

        self.assertEqual(len(rows), 2)
        data_row = rows[1]

        self.assertEqual(data_row[0], "Critical DB Password")
        self.assertEqual(data_row[1], self.secret_needs_change.hashid)
        self.assertEqual(data_row[4], "needs changing")
        self.assertTrue(len(data_row[7]) > 0)

    def test_search_filtering(self):
        """Ensure ?q= param filters both CSV and JSON."""

        self.client.force_authenticate(user=self.admin_user)

        # 1a. Search for non-existent (JSON)
        api_url = reverse('accounts.api.user-pending-secrets', kwargs={'username': self.target_user.username})
        response = self.client.get(api_url, {'q': 'Banana'})
        results = response.json()['results'] if 'results' in response.json() else response.json()
        self.assertEqual(len(results), 0, "JSON API should return 0 results for 'Banana'")

        # 1b. Search for existing (JSON)
        response = self.client.get(api_url, {'q': 'Critical'})
        results = response.json()['results'] if 'results' in response.json() else response.json()
        self.assertEqual(len(results), 1, "JSON API should return 1 result for 'Critical'")

        # 2. Test CSV Export Filtering
        self.client.force_login(user=self.admin_user)
        csv_url = reverse('accounts.user-pending-secrets-csv', kwargs={'username': self.target_user.username})

        # 2a. Search for non-existent (CSV)
        response = self.client.get(csv_url, {'q': 'Banana'})
        content = response.content.decode('utf-8')
        rows = list(csv.reader(io.StringIO(content)))

        self.assertEqual(len(rows), 1, "CSV should only contain header when search finds nothing")

        # 2b. Search for existing (CSV)
        response = self.client.get(csv_url, {'q': 'Critical'})
        content = response.content.decode('utf-8')
        rows = list(csv.reader(io.StringIO(content)))

        self.assertEqual(len(rows), 2, "CSV should contain header + 1 row when search matches")
        self.assertEqual(rows[1][0], "Critical DB Password")
