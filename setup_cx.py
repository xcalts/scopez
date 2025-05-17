import cx_Freeze  # type: ignore

import os

from .setup import read_version


cx_Freeze.setup(
    name="scopez",
    version=read_version(),
    author="Christos Kaltsas",
    author_email="christos@xcalts.co",
    python_requires=">3.12.5",
    description="Scopez is a Python scope analysis tool built with simplicity in mind. It is intended to help verify the scope during bug bounty programs and penetration testing.",
    url="https://github.com/xcalts/scopez",
    options={
        "build_exe": {
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
