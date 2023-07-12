from importlib.metadata import version, PackageNotFoundError

try:
    # Consider TeamVault installed via pip
    VERSION_STRING = version('teamvault')
except PackageNotFoundError:
    VERSION_STRING = 'dev'
