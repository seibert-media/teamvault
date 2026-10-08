import threading
from configparser import ConfigParser
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from teamvault.apps.settings.config import configure_data_dir, configure_share_reason


class ConfigureDataDirTest(SimpleTestCase):
    def test_concurrent_calls_do_not_interfere(self):
        # Regression test: gunicorn and huey import settings simultaneously at
        # boot, so the write test must not race against other processes
        # running it on the same data_dir at the same time.
        thread_count = 8
        rounds = 50
        barrier = threading.Barrier(thread_count)
        errors = []

        def worker():
            for _ in range(rounds):
                barrier.wait()
                try:
                    configure_data_dir(ConfigParser())
                except Exception as exc:
                    errors.append(exc)

        with TemporaryDirectory() as data_dir, patch.dict('os.environ', {'TEAMVAULT_DATA_DIR': data_dir}):
            threads = [threading.Thread(target=worker) for _ in range(thread_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        self.assertEqual(errors, [])


def _configure_share_reason(config_text: str) -> SimpleNamespace:
    config = ConfigParser()
    config.read_string(config_text)
    settings = SimpleNamespace()
    configure_share_reason(config, settings)
    return settings


class ConfigureShareReasonTest(SimpleTestCase):
    def test_requires_reason_by_default(self):
        settings = _configure_share_reason('[teamvault]\n')
        self.assertTrue(settings.REQUIRE_SHARE_REASON)

    def test_can_be_disabled(self):
        settings = _configure_share_reason('[teamvault]\nrequire_share_reason = false\n')
        self.assertFalse(settings.REQUIRE_SHARE_REASON)
