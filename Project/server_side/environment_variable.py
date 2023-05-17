import os


def make_environment_key(key, keyName):
    """Function receives a value and a name, that represents the provided value, as parameter.
    This function makes an environment variable named and values as given."""
    os.environ[keyName] = key


API_KEY = "74ab4f71a63dfd057b157d4223eb110d8566f3c0ea945e09e4f5632e57883560"  # VirusTotal API key
make_environment_key(API_KEY, 'VT_API')
