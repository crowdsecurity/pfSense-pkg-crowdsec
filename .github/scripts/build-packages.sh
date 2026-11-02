#!/bin/sh
#
# Build crowdsec, crowdsec-firewall-bouncer and pfSense-pkg-crowdsec with
# poudriere, for one FreeBSD version / architecture, and pack them in a tar
# archive with the layout expected by install-crowdsec.sh.
#
# Must run as root on a FreeBSD host that can execute the jail binaries
# natively: amd64 jails on amd64, arm64 and armv7 jails on arm64 (32-bit
# compat). The host kernel should also be >= the jail version.
#
# environment:
#   JAIL_VERSION    poudriere jail -v        (e.g. 14, 15, 16)
#   JAIL_METHOD     poudriere jail -m        (e.g. pkgbase=base_release_5, pkgbase=base_latest)
#   JAIL_URL        poudriere jail -U        (default: pkg+https://pkg.freebsd.org)
#   JAIL_ARCH       poudriere jail -a        (amd64 | arm64.aarch64 | armv7)
#   ARCHIVE         output tar file
#   PACKAGING_REPO  crowdsec ports overlay   (default: crowdsecurity/packaging-freebsd)
#   PACKAGING_REF   branch of the overlay    (default: crowdsec-wasm)
#   PORTS_REPO      FreeBSD ports tree       (default: github mirror of freebsd-ports)
#   PORTS_BRANCH    branch of the ports tree (default: main)
#   LOGS_DIR        where to copy poudriere logs (default: ./poudriere-logs)

set -eu

: "${JAIL_VERSION:?}" "${JAIL_METHOD:?}" "${JAIL_ARCH:?}" "${ARCHIVE:?}"
JAIL_URL=${JAIL_URL:-pkg+https://pkg.freebsd.org}

case "$ARCHIVE" in
    /*) OUTPUT=$ARCHIVE ;;
    *) OUTPUT=$(pwd)/$ARCHIVE ;;
esac

PACKAGING_REPO=${PACKAGING_REPO:-https://github.com/crowdsecurity/packaging-freebsd.git}
PACKAGING_REF=${PACKAGING_REF:-crowdsec-wasm}
PORTS_REPO=${PORTS_REPO:-https://github.com/freebsd/freebsd-ports.git}
PORTS_BRANCH=${PORTS_BRANCH:-main}
LOGS_DIR=${LOGS_DIR:-$(pwd)/poudriere-logs}

# this repository is itself a ports overlay (security/pfSense-pkg-crowdsec)
OVERLAY_DIR=$(cd "$(dirname "$0")/../.." && pwd)

BASEFS=/usr/local/poudriere
JAIL=$(echo "j${JAIL_VERSION}_${JAIL_ARCH}" | tr -c 'A-Za-z0-9\n' '_')
PTREE=freebsd

# packages built from our overlays, never fetch them from pkg.FreeBSD.org
OWN_PACKAGES="crowdsec-firewall-bouncer crowdsec pfSense-pkg-crowdsec"

collect_logs() {
    mkdir -p "$LOGS_DIR"
    if [ -d "$BASEFS/data/logs/bulk" ]; then
        # follow the "latest" symlinks, keep only per-port logs
        find -L "$BASEFS/data/logs/bulk" -path '*/latest/logs/*' -name '*.log' \
            -exec cp {} "$LOGS_DIR"/ \; 2>/dev/null || :
    fi
}
trap collect_logs EXIT

echo "::group::Host"
uname -a
sysctl -n kern.supported_archs 2>/dev/null || :
echo "::endgroup::"

echo "::group::Configure poudriere"
cat > /usr/local/etc/poudriere.conf <<EOT
NO_ZFS=yes
BASEFS=$BASEFS
DISTFILES_CACHE=/usr/ports/distfiles
RESOLV_CONF=/etc/resolv.conf
USE_TMPFS=no
USE_PORTLINT=no
ALLOW_MAKE_JOBS=yes
CHECK_CHANGED_OPTIONS=verbose
CHECK_CHANGED_DEPS=yes
# fetch build dependencies (go, pkgconf...) from the official repository
# instead of building them: the arm VMs are emulated, every build is slow
PACKAGE_FETCH_BRANCH=latest
PACKAGE_FETCH_BLACKLIST="$OWN_PACKAGES"
EOT
mkdir -p /usr/ports/distfiles
cat /usr/local/etc/poudriere.conf
echo "::endgroup::"

echo "::group::Create jail $JAIL (-v $JAIL_VERSION -a $JAIL_ARCH -m $JAIL_METHOD)"
# explicit pkgbase repository: the default can select the wrong base for armv7
poudriere jail -c -j "$JAIL" -v "$JAIL_VERSION" -a "$JAIL_ARCH" \
    -m "$JAIL_METHOD" -U "$JAIL_URL"
poudriere jail -l
echo "::endgroup::"

echo "::group::Create ports trees"
poudriere ports -c -p "$PTREE" -m git+https -U "$PORTS_REPO" -B "$PORTS_BRANCH" -D
poudriere ports -c -p crowdsec -m git+https -U "$PACKAGING_REPO" -B "$PACKAGING_REF" -D
poudriere ports -c -p pfsense -m null -M "$OVERLAY_DIR"
poudriere ports -l
echo "::endgroup::"

echo "::group::Build packages"
poudriere bulk -j "$JAIL" -p "$PTREE" -O crowdsec -O pfsense security/pfSense-pkg-crowdsec
echo "::endgroup::"

echo "::group::Create $OUTPUT"
# All is a symlink to .latest/All (poudriere commits atomically): use find -L
PKGDIR="$BASEFS/data/packages/${JAIL}-${PTREE}/All"
STAGING=$(mktemp -d)

files=""
for name in $OWN_PACKAGES; do
    # a digit right after the name, to avoid matching other packages
    found=$(find -L "$PKGDIR" -maxdepth 1 -name "${name}-[0-9]*.pkg")
    if [ "$(echo "$found" | grep -c .)" -ne 1 ]; then
        echo "Error: expected exactly one package for $name in $PKGDIR, found: '$found'" >&2
        exit 1
    fi
    pkg info -F "$found" | grep -E '^(Name|Version|Architecture)'
    cp "$found" "$STAGING"/
    files="$files $(basename "$found")"
done

# pfSense manages abseil/re2 itself: crowdsec must not depend on them
crowdsec_pkg=$(find "$STAGING" -name 'crowdsec-[0-9]*.pkg')
if { pkg info -d -F "$crowdsec_pkg"; pkg info -B -F "$crowdsec_pkg"; } | grep -Eqi 'abseil|absl|re2'; then
    echo "Error: crowdsec depends on abseil/re2, wrong packaging branch?" >&2
    pkg info -d -B -F "$crowdsec_pkg" >&2
    exit 1
fi

# plain (uncompressed) tar, flat layout, like the previous releases
# shellcheck disable=SC2086
tar -cvf "$OUTPUT" -C "$STAGING" $files
rm -rf "$STAGING"
echo "::endgroup::"
