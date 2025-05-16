import setuptools  # type: ignore

import os


def read_version():
    """Read the CLI tool's version from `./src/__version__.py`"""
    version_file = os.path.join(os.path.dirname(__file__), "src", "__version__.py")
    with open(version_file) as f:
        for line in f:
            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]


setuptools.setup(
    name="scopez",
    version=read_version(),
    author="Christos Kaltsas",
    python_requires=">3.12.5",
    author_email="christos@xcalts.co",
    description="Scopez is a targets analyzer tool written in python with a focus in simplicity. Designed to be used in combination with other tools for checking the scope in bug bounties and pentests.",
    url="https://github.com/xcalts/scopez",
    packages=setuptools.find_packages(where="src"),
    package_dir={"": "src"},
    include_package_data=True,
    install_requires=[
        # Command-line interface
        "Click",
        # REST HTTP Client
        "requests",
        # Rich text and beautiful formatting in the terminal.
        "rich",
        # Pydantic is the most widely used data validation library for Python.
        "pydantic",
    ],
    entry_points={
        "console_scripts": [
            "scopez=main:cli",
        ],
    },
)
