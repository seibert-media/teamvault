from pathlib import Path


def configure_webpack(settings):
    settings.WEBPACK_LOADER = {
        'DEFAULT': {
            'CACHE': not settings.DEBUG,
            'BUNDLE_DIR_NAME': 'bundled/',  # must end with slash
            'STATS_FILE': str(Path(settings.PROJECT_ROOT) / 'webpack-stats.json'),
            'POLL_INTERVAL': 0.1,
            'TIMEOUT': None,
            'IGNORE': [r'.+\.hot-update.js', r'.+\.map'],
            'LOADER_CLASS': 'webpack_loader.loader.WebpackLoader',
        }
    }
