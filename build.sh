#!/usr/bin/env bash
# Build btfree.prx using the official pspdev toolchain inside Docker.
# No local PSP SDK required -- only Docker.
#
# Usage: ./build.sh
set -euo pipefail

cd "$(dirname "$0")"

docker run --rm -v "$PWD":/w -w /w pspdev/pspdev:latest bash -lc '
  export PATH=/usr/local/pspdev/bin:$PATH
  make clean
  make PSPSDK=/usr/local/pspdev/psp/sdk
'

echo
echo "Built: $(ls -la btfree.prx)"
mkdir -p dist
cp -f btfree.prx dist/btfree.prx
echo "Copied to dist/btfree.prx"
