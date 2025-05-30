import cx_Freeze  # type: ignore


cx_Freeze.setup(
    name="scopez",
    version="v0.0.5",
    author="Christos Kaltsas",
    author_email="christos@xcalts.co",
    python_requires=">3.12.5",
    description="Scopez verifies connectivity to target servers, reveals CDN presence, and provides detailed target insights like reachability and RDAP.",
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
