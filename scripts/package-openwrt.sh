#!/bin/bash
# package-openwrt.sh — build installable .ipk and .apk packages for OpenWrt
# from a pre-built static binary.
#
# Usage: scripts/package-openwrt.sh <binary> <openwrt-arch> <version> <dest-dir>
#   <binary>       path to the static linux binary (e.g. dist/bypasscore-openwrt-x86_64)
#   <openwrt-arch> OpenWrt architecture (e.g. x86_64, aarch64_cortex-a53)
#   <version>      package version without leading 'v' (e.g. 1.0.2)
#   <dest-dir>     output directory
#
# Produces:
#   <dest>/bypasscore_<version>_<arch>.ipk   (opkg, all OpenWrt versions)
#   <dest>/bypasscore-<version>_<arch>.apk   (apk,  OpenWrt 23.05+ / 25.12.0+)
#
# Requirements:
#   - GNU tar + gzip (for ipkg-build) — present on Ubuntu CI runners.
#   - Docker (for apk mkpkg via alpine:edge container) — present on GitHub runners.
#
# The package installs the binary to /usr/bin/bypasscore. No init script is
# included: BypassCore is a routing-engine library/CLI; the upper layer
# (gateway/TUN) is responsible for daemonizing and invoking it.
set -euo pipefail

binary="$1"
owrt_arch="$2"
version="$3"
dest="$4"

if [ ! -f "$binary" ]; then
    echo "*** Error: binary not found: $binary" >&2
    exit 1
fi

pkg_name="bypasscore"
description="Standalone routing engine: rule matching -> routing decision."
script_dir="$(cd "$(dirname "$0")" && pwd)"
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# --- Package rootfs layout: /usr/bin/bypasscore ---
rootfs="$workdir/rootfs"
mkdir -p "$rootfs/usr/bin"
cp "$binary" "$rootfs/usr/bin/bypasscore"
chmod 0755 "$rootfs/usr/bin/bypasscore"

# ============================================================
# .ipk (opkg) — uses the vendored ipkg-build script.
# ipkg-build needs GNU tar (--sort=name, --format=gnu); Ubuntu runners have it.
# ============================================================
echo ">>> Building .ipk for $owrt_arch ..."
mkdir -p "$rootfs/CONTROL"
cat > "$rootfs/CONTROL/control" <<EOF
Package: $pkg_name
Version: $version
Architecture: $owrt_arch
Maintainer: kinmeic
Section: net
Priority: optional
Description: $description
Depends:
EOF

# ipkg-build writes <name>_<version>_<arch>.ipk into the destination dir.
bash "$script_dir/ipkg-build" "$rootfs" "$dest" || {
    echo "*** Error: ipkg-build failed" >&2
    exit 1
}
# Normalize the output name for predictability.
ipk_out="$dest/${pkg_name}_${version}_${owrt_arch}.ipk"
if [ ! -f "$ipk_out" ]; then
    echo "*** Error: expected $ipk_out not produced" >&2
    exit 1
fi
echo "    ✓ $(basename "$ipk_out") ($(du -h "$ipk_out" | cut -f1))"

# ============================================================
# .apk (apk-tools v3) — built inside an alpine:edge container which ships
# apk-tools 3.x with the `mkpkg` applet. The host (Ubuntu) has no apk v3.
# ============================================================
echo ">>> Building .apk for $owrt_arch ..."
apk_out="$dest/${pkg_name}-${version}_${owrt_arch}.apk"

# Run apk mkpkg in alpine:edge, mounting the rootfs + dest as a shared volume.
# --info supplies the .PKGINFO fields; --files is the payload tree.
docker run --rm \
    -v "$rootfs:/pkg:ro" \
    -v "$dest:/out" \
    alpine:edge \
    sh -c "apk add --no-cache apk-tools >/dev/null 2>&1; \
           apk mkpkg \
             --output /out/$(basename "$apk_out") \
             --info name:$pkg_name \
             --info version:$version \
             --info arch:$owrt_arch \
             --info description:'$description' \
             --info license:MIT \
             --info maintainer:kinmeic \
             --info url:https://github.com/kinmeic/BypassCore \
             --files /pkg"

if [ ! -f "$apk_out" ]; then
    echo "*** Error: $apk_out not produced" >&2
    exit 1
fi
echo "    ✓ $(basename "$apk_out") ($(du -h "$apk_out" | cut -f1))"
