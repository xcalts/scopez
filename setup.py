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
    author_email="christos@xcalts.co",
    python_requires=">3.12.5",
    description="Scopez is a Python scope analysis tool built with simplicity in mind. It is intended to help verify the scope during bug bounty programs and penetration testing.",
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
        # Retrieve and parse whois data for IPv4 and IPv6 addresses.
        "ipwhois",
    ],
    entry_points={
        "console_scripts": [
            "scopez=main:cli",
        ],
    },
)
