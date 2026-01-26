#!/usr/bin/env pwsh
#
# Bump project version in all relevant files, commit & tag the release, and push to remote.
#

# Enable strict mode (similar to bash's set -euo pipefail)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ------------------------------------------------------------------------------
# Print usage and exit if no version argument provided
# ------------------------------------------------------------------------------
if ($args.Count -lt 1) {
    Write-Host "Usage: $($MyInvocation.MyCommand.Name) <new_version>"
    Write-Host "Example: $($MyInvocation.MyCommand.Name) 1.2.3"
    exit 1
}

$NEW_VERSION = $args[0]
Write-Host "🚀 Starting version bump to $NEW_VERSION"
Write-Host

# ------------------------------------------------------------------------------
# Update version in pyproject.toml
# ------------------------------------------------------------------------------
Write-Host "🔄 Updating version in pyproject.toml..."
(Get-Content pyproject.toml) -replace '^version = ".*"', "version = `"$NEW_VERSION`"" | Set-Content pyproject.toml
Write-Host "   → pyproject.toml updated."

# ------------------------------------------------------------------------------
# Update version in src/__version__.py
# ------------------------------------------------------------------------------
Write-Host "🔄 Updating version in src/__version__.py..."
(Get-Content src/__version__.py) -replace '^__version__ = ".*"', "__version__ = `"$NEW_VERSION`"" | Set-Content src/__version__.py
Write-Host "   → src/__version__.py updated."
Write-Host

# ------------------------------------------------------------------------------
# Commit changes
# ------------------------------------------------------------------------------
Write-Host "📝 Staging and committing version bump..."
git add pyproject.toml src/__version__.py
git commit -m "feat: bump version to $NEW_VERSION"
Write-Host "   → Commit created."

# ------------------------------------------------------------------------------
# Push commit
# ------------------------------------------------------------------------------
Write-Host "📤 Pushing commit to origin/main..."
git push origin main
Write-Host "   → Push complete."

# ------------------------------------------------------------------------------
# Create and push Git tag
# ------------------------------------------------------------------------------
Write-Host "🏷️  Creating annotated tag '$NEW_VERSION'..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"
Write-Host "📤 Pushing tag to origin..."
git push origin "$NEW_VERSION"
Write-Host "   → Tag pushed."
Write-Host

Write-Host "✅ Version bump to $NEW_VERSION completed successfully!"