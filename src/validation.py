import click

import os
import hashlib


def validate_file_exists(ctx, param, value):
    if not _file_exists(value) and value != '':
        raise click.BadParameter(f"the file '{value}' does not exist.")

    return value


def validate_png_filename(ctx, param, value):
    if not value.lower().endswith('.png'):
        raise click.BadParameter("Output filename must end with '.png'.")
    return value


def _file_exists(filepath: str) -> bool:
    """
    Checks if a file exists at the given path.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: `True` if the file exists, otherwise `False`.

    """
    return os.path.exists(filepath)


def _verify_sha256(filepath: str, expected_hash: str) -> bool:
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)

    file_hash = sha256.hexdigest()

    return file_hash == expected_hash.lower()
