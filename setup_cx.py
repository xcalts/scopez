import cx_Freeze  # type: ignore

import os


def read_version() -> str:
    """Read the CLI tool's version from `./src/__version__.py`"""
    version_file = os.path.join(os.path.dirname(__file__), "src", "__version__.py")
    with open(version_file) as f:
        for line in f:
            if line.startswith("__version__"):
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]


cx_Freeze.setup(
    name="scopez",
    version=read_version(),
    author="",
    python_requires=">3.12.5",
    description="Scopez is a targets analyzer tool written in python with a focus in simplicity. Designed to be used in combination with other tools for checking the scope in bug bounties and pentests.",
    url="https://github.com/xcalts/scopez",
    options={
        "build_exe": {
            "packages": [],  # Include required packages
            "excludes": ["tests", "docs"],  # Exclude unnecessary files
            "build_exe": "build/",  # Output directory for the build
        }
    },
    executables=[
        cx_Freeze.Executable(
            script="src/main.py",  # Your main script (entry point)
            target_name="scopez",  # Name of the generated executable
        )
    ],
)
