#!/usr/bin/env bash

#
# Build the python package and publish it to PyPI.
#

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Print usage and exit if no token argument provided
# ------------------------------------------------------------------------------
if [ $# -lt 1 ]; then
  echo "Usage: $0 <pypi_token>"
  echo "Example: $0 pypi-AgEIcHlwaS5vcmc..."
  exit 1
fi

PYPI_TOKEN="$1"

# ------------------------------------------------------------------------------
# Run from the project root regardless of where the script is called from
# ------------------------------------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# ------------------------------------------------------------------------------
# Create an isolated virtual environment for the build tools
# ------------------------------------------------------------------------------
BUILD_VENV="$(mktemp -d)"
trap 'rm -rf "$BUILD_VENV"' EXIT

echo "🐍 Creating build environment..."
python3 -m venv "$BUILD_VENV"
echo "   → $BUILD_VENV"

# ------------------------------------------------------------------------------
# Install build tools
# ------------------------------------------------------------------------------
echo "📦 Installing build tools..."
"$BUILD_VENV/bin/python" -m pip install --quiet --upgrade pip build twine
echo "   → build and twine installed."

# ------------------------------------------------------------------------------
# Build the package (clean dist/ first so stale builds are never uploaded)
# ------------------------------------------------------------------------------
echo "🔨 Building the package..."
rm -rf dist
"$BUILD_VENV/bin/python" -m build
echo "   → Package built in dist/."

# ------------------------------------------------------------------------------
# Publish to PyPI
# ------------------------------------------------------------------------------
echo "🚀 Publishing to PyPI..."
TWINE_USERNAME="__token__" TWINE_PASSWORD="$PYPI_TOKEN" \
  "$BUILD_VENV/bin/python" -m twine upload --non-interactive dist/*
echo "   → Published."

echo
echo "✅ Done."
