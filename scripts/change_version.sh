#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <new_version>"
  exit 1
fi

NEW_VERSION="$1"

# Update pyproject.toml
sed -i '' -E "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml

# Update setup_cx.py
sed -i '' -E "s/(version=)\"[^\"]+\"/\1\"$NEW_VERSION\"/" setup_cx.py

# Update src/__version__.py
sed -i '' -E "s/^__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" src/__version__.py

echo "Version updated to $NEW_VERSION in:
- pyproject.toml
- setup_cx.py
- src/__version__.py"

echo "Pushing to Github"
git add -A
git commit -m "feat: $NEWVERSION"
git push origin main
git tag -a "$NEW_VERSION" -m "$NEW_VERSION"
git push origin "$NEW_VERSION"
