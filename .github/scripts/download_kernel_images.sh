#!/usr/bin/env bash
#
# Download Ubuntu mainline-PPA kernel .debs for the integration test.
#
# Usage: download_kernel_images.sh <out_dir> <version>...
#   e.g. download_kernel_images.sh tmp/integration/kernels 6.5 6.8 7.0
#
# For each version it fetches the two amd64 generic debs the `vm` runner needs:
#   linux-image-unsigned-<ver>-generic  (the bootable vmlinuz)
#   linux-modules-<ver>-generic         (/lib/modules, incl. veth.ko.zst)
# The build-timestamp in the filenames is discovered from the directory index,
# so this keeps working when the PPA rebuilds a version.
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <out_dir> <version>..." >&2
  exit 1
fi

out_dir=$1
shift
mkdir -p "$out_dir"

base="https://kernel.ubuntu.com/~kernel-ppa/mainline"

for ver in "$@"; do
  dir="$base/v$ver/amd64/"
  echo "==> listing $dir"
  index=$(curl -fsSL "$dir")

  for kind in linux-image-unsigned linux-modules; do
    file=$(printf '%s\n' "$index" \
      | grep -oE "${kind}-[0-9][^\"'<> ]*-generic_[^\"'<> ]*_amd64\.deb" \
      | sort -u | head -n1) || true
    if [ -z "${file:-}" ]; then
      echo "error: no ${kind} generic amd64 deb found for v$ver at $dir" >&2
      echo "       (if v$ver is missing, pick another mainline version)" >&2
      exit 1
    fi
    echo "    fetching $file"
    curl -fsSL --output-dir "$out_dir" --remote-name-all "$dir$file"
  done
done

echo "==> downloaded into $out_dir:"
ls -la "$out_dir"
