# AGENTS.md

Guidance for AI coding agents working in this repository.

## Overview

Scopez verifies connectivity to target servers, reveals CDN presence, and provides detailed target insights like reachability and RDAP.

## Key commands

### Setup

```bash
# Activate the virtual environment.
.venv/Scripts/Activate

# Install all the dependencies.
pip install -e .
```

### Run

### Code quality

```bash
# Format code
ruff check --fix
```

## Development workflow

### Key development principles

- **Imports**
    - Only `import A`. 
    - Don't use `from A import B`.
    - Don't use `import A as a`
    - At the start of a file. The order of importing is:
        1. External packages imports.
        2. Native packages imports.
        3. Current directory imnports
- **Functions**
    - Don't create functions inside a function.
    - Don't create helper functions unless prompted to.
- **No abbreviations** 
    - In variable names (`user` not `u`, `fieldMetadata` not `fm`)

### Naming conventions

- **Variables/functions**: snake_case
- **Constants**: SCREAMING_SNAKE_CASE
- **Types/Classes**: PascalCase
- **Files/directories**: `file.py`

### Notes

- Do not write tests.

### Comments

- Use short-form comments (`#`)
- Explain WHY (business logic), not WHAT
- Do not comment obvious code

### Before Making Changes

1. Always run linting (`ruff check --fix`) after code changes.
2. Always run the command to validate that it works.