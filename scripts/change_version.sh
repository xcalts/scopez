#!/usr/bin/env bash
#
# Bump project version in all relevant files, commit & tag the release, and push to remote.
#

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Print usage and exit if no version argument provided
# ------------------------------------------------------------------------------
if [ $# -lt 1 ]; then
  echo "Usage: $0 <new_version>"
  echo "Example: $0 1.2.3"
  exit 1
fi

NEW_VERSION="$1"
echo "🚀 Starting version bump to $NEW_VERSION"
echo

# ------------------------------------------------------------------------------
# Update version in pyproject.toml
# ------------------------------------------------------------------------------
echo "🔄 Updating version in pyproject.toml..."
sed -i '' -E "s/^version = \".*\"/version = \"$NEW_VERSION\"/" pyproject.toml
echo "   → pyproject.toml updated."

# ------------------------------------------------------------------------------
# Update version in setup_cx.py
# ------------------------------------------------------------------------------
echo "🔄 Updating version in setup_cx.py..."
sed -i '' -E "s/(version=)\"[^\"]+\"/\1\"$NEW_VERSION\"/" setup_cx.py
echo "   → setup_cx.py updated."

# ------------------------------------------------------------------------------
# Update version in src/__version__.py
# ------------------------------------------------------------------------------
echo "🔄 Updating version in src/__version__.py..."
sed -i '' -E "s/^__version__ = \".*\"/__version__ = \"$NEW_VERSION\"/" src/__version__.py
echo "   → src/__version__.py updated."

echo

# ------------------------------------------------------------------------------
# Commit changes
# ------------------------------------------------------------------------------
echo "📝 Staging and committing version bump..."
git add pyproject.toml setup_cx.py src/__version__.py
git commit -m "feat: bump version to $NEW_VERSION"
echo "   → Commit created."

# ------------------------------------------------------------------------------
# Push commit
# ------------------------------------------------------------------------------
echo "📤 Pushing commit to origin/main..."
git push origin main
echo "   → Push complete."

# ------------------------------------------------------------------------------
# Create and push Git tag
# ------------------------------------------------------------------------------
echo "🏷️  Creating annotated tag '$NEW_VERSION'..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"
echo "📤 Pushing tag to origin..."
git push origin "$NEW_VERSION"
echo "   → Tag pushed."

echo
echo "✅ Version bump to $NEW_VERSION completed successfully!"
