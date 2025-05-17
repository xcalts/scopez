import click

import os


def validate_file_exists(ctx, param, value):
    if not _file_exists(value) and value != "":
        raise click.BadParameter(f"the file '{value}' does not exist.")

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
