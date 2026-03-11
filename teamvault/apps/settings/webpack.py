from pathlib import Path


def configure_webpack(settings):
    stats_file = Path(settings.PROJECT_ROOT) / 'webpack-stats.json'
    loader_class = (
        'webpack_loader.loaders.WebpackLoader'
        if stats_file.exists()
        else 'webpack_loader.loaders.FakeWebpackLoader'
    )
    settings.WEBPACK_LOADER = {
        'DEFAULT': {
            'CACHE': not settings.DEBUG,
            'BUNDLE_DIR_NAME': 'bundled/',  # must end with slash
            'STATS_FILE': str(stats_file),
            'POLL_INTERVAL': 0.1,
            'TIMEOUT': None,
            'IGNORE': [r'.+\.hot-update.js', r'.+\.map'],
            'LOADER_CLASS': loader_class,
        }
    }
