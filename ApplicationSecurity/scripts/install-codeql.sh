#!/usr/bin/env sh
# Installs the CodeQL CLI bundle into ./tools/codeql (used automatically as the primary SAST engine).
# Download size is roughly 500-700 MB. Check the GitHub CodeQL terms for use on private/commercial code.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)" in
  Darwin) PLATFORM=osx64 ;;
  *) PLATFORM=linux64 ;;
esac
URL="https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-${PLATFORM}.tar.gz"
mkdir -p "$ROOT/tools"
rm -rf "$ROOT/tools/codeql"
echo "Downloading $URL"
curl -fsSL "$URL" | tar -xz -C "$ROOT/tools"
"$ROOT/tools/codeql/codeql" version
echo "CodeQL installed. Restart the server; the Analysis Agent picks up tools/codeql automatically."
