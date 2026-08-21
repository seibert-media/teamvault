import threading
from configparser import ConfigParser
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase

from teamvault.apps.settings.config import configure_data_dir


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
