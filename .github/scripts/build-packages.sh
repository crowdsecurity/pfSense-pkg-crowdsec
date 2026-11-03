#!/bin/sh
#
# Build crowdsec, crowdsec-firewall-bouncer and pfSense-pkg-crowdsec for one
# FreeBSD major version and one architecture, on an amd64 host.
#
# - TARGET=amd64: poudriere bulk in a pkgbase jail.
# - TARGET=arm64 / armv7: cross-compiled with the ports framework
#   (CROSS_TOOLCHAIN + CROSS_SYSROOT): native amd64 Go and clang, cgo enabled
#   (mattn sqlite), against a sysroot installed from the target's pkgbase
#   repository. pfSense-pkg-crowdsec (NO_ARCH) is packaged against the
#   sysroot's package database, where the cross-built crowdsec and bouncer are
#   registered, so that its dependencies are recorded.
#
# The result is out/freebsd-<major>-<arch>.tar (plain tar, flat layout), as
# expected by install-crowdsec.sh.
#
# Must run as root on an amd64 FreeBSD host. The host kernel should be >= the
# target version for the amd64 jail.
#
# environment:
#   FREEBSD_MAJOR   target FreeBSD major version  (14, 15, 16)
#   BASE_REPO       pkgbase repository             (base_release_5, base_release_1, base_latest)
#   TARGET          architecture to build          (amd64, arm64, armv7)
#   PKG_URL         package mirror                 (default: pkg+https://pkg.freebsd.org)
#   OUT_DIR         output directory               (default: ./out)
#   PACKAGING_REPO  crowdsec ports overlay         (default: crowdsecurity/packaging-freebsd)
#   PACKAGING_REF   branch of the overlay          (default: crowdsec-wasm)
#   PORTS_REPO      FreeBSD ports tree             (default: github mirror of freebsd-ports)
#   PORTS_BRANCH    branch of the ports tree       (default: main)
#   LOGS_DIR        where to copy the build logs   (default: ./build-logs)

set -eu

: "${FREEBSD_MAJOR:?}" "${BASE_REPO:?}" "${TARGET:?}"
# never wait for a confirmation
export ASSUME_ALWAYS_YES=yes
PKG_URL=${PKG_URL:-pkg+https://pkg.freebsd.org}
OUT_DIR=$(mkdir -p "${OUT_DIR:-out}" && cd "${OUT_DIR:-out}" && pwd)
LOGS_DIR=$(mkdir -p "${LOGS_DIR:-build-logs}" && cd "${LOGS_DIR:-build-logs}" && pwd)

PACKAGING_REPO=${PACKAGING_REPO:-https://github.com/crowdsecurity/packaging-freebsd.git}
PACKAGING_REF=${PACKAGING_REF:-crowdsec-wasm}
PORTS_REPO=${PORTS_REPO:-https://github.com/freebsd/freebsd-ports.git}
PORTS_BRANCH=${PORTS_BRANCH:-main}

# this repository is itself a ports overlay (security/pfSense-pkg-crowdsec)
OVERLAY_DIR=$(cd "$(dirname "$0")/../.." && pwd)

BASEFS=/usr/local/poudriere
JAIL=j${FREEBSD_MAJOR}_amd64
PTREE=freebsd
DISTDIR=/usr/ports/distfiles
CROSS_BASE=/usr/local/cross

# packages built from our overlays, never fetch them from pkg.FreeBSD.org
OWN_PACKAGES="crowdsec-firewall-bouncer crowdsec pfSense-pkg-crowdsec"
# the architecture-specific ones, cross-compiled for arm
CROSS_PORTS="security/crowdsec-firewall-bouncer security/crowdsec"

collect_logs() {
    if [ -d "$BASEFS/data/logs/bulk" ]; then
        # follow the "latest" symlinks, keep only per-port logs
        find -L "$BASEFS/data/logs/bulk" -path '*/latest/logs/*' -name '*.log' \
            -exec cp {} "$LOGS_DIR"/ \; 2>/dev/null || :
    fi
}
trap collect_logs EXIT

# find exactly one <name>-<version>.pkg in a directory (following symlinks)
find_pkg() {
    _found=$(find -L "$1" -maxdepth 1 -name "$2-[0-9]*.pkg")
    if [ "$(echo "$_found" | grep -c .)" -ne 1 ]; then
        echo "Error: expected exactly one package for $2 in $1, found: '$_found'" >&2
        return 1
    fi
    echo "$_found"
}

# make_archive <asset arch> <expected ABI> <crowdsec.pkg> <bouncer.pkg> <pfSense-pkg.pkg>
make_archive() {
    _asset=$1 _abi=$2
    shift 2
    _archive="$OUT_DIR/freebsd-$FREEBSD_MAJOR-$_asset.tar"
    echo "::group::Create $_archive"

    _crowdsec=$1 _plugin=$3
    for _p in "$@"; do
        printf '%-45s %s\n' "$(basename "$_p")" "$(pkg query -F "$_p" '%q')"
    done

    # the binaries must be for the target, the packages labelled accordingly
    for _p in "$1" "$2"; do
        _q=$(pkg query -F "$_p" '%q')
        if [ "$_q" != "$_abi" ]; then
            echo "Error: $(basename "$_p") is for $_q, expected $_abi" >&2
            return 1
        fi
    done
    _bin=$(tar -tf "$_crowdsec" | grep '/bin/crowdsec$')
    tar -xOf "$_crowdsec" "$_bin" | file -

    # pfSense-pkg-crowdsec has no binaries: NO_ARCH, valid for any architecture
    _q=$(pkg query -F "$_plugin" '%q')
    if [ "$_q" != "FreeBSD:$FREEBSD_MAJOR:*" ]; then
        echo "Error: $(basename "$_plugin") is for $_q, expected FreeBSD:$FREEBSD_MAJOR:*" >&2
        return 1
    fi
    # ...and it must depend on crowdsec and the bouncer
    pkg info -d -F "$_plugin"
    for _d in crowdsec crowdsec-firewall-bouncer; do
        if ! pkg query -F "$_plugin" '%dn' | grep -qx "$_d"; then
            echo "Error: $(basename "$_plugin") does not depend on $_d" >&2
            return 1
        fi
    done

    # pfSense manages abseil/re2 itself: crowdsec must not depend on them
    if { pkg info -d -F "$_crowdsec"; pkg info -B -F "$_crowdsec"; } | grep -Eqi 'abseil|absl|re2'; then
        echo "Error: crowdsec depends on abseil/re2, wrong packaging branch?" >&2
        pkg info -d -B -F "$_crowdsec" >&2
        return 1
    fi

    _staging=$(mktemp -d)
    cp "$@" "$_staging"/
    # plain (uncompressed) tar, flat layout, like the previous releases
    (cd "$_staging" && tar -cvf "$_archive" -- *.pkg)
    rm -rf "$_staging"
    echo "::endgroup::"
}

echo "::group::Host"
uname -a
echo "FreeBSD $FREEBSD_MAJOR ($BASE_REPO), target: $TARGET"
echo "::endgroup::"

#
# amd64, and the NO_ARCH pfSense-pkg-crowdsec: poudriere
#

build_amd64() {
    echo "::group::Configure poudriere"
    cat > /usr/local/etc/poudriere.conf <<EOT
NO_ZFS=yes
BASEFS=$BASEFS
DISTFILES_CACHE=$DISTDIR
RESOLV_CONF=/etc/resolv.conf
USE_TMPFS=no
USE_PORTLINT=no
ALLOW_MAKE_JOBS=yes
CHECK_CHANGED_OPTIONS=verbose
CHECK_CHANGED_DEPS=yes
# fetch build dependencies (go, pkgconf...) instead of building them
PACKAGE_FETCH_BRANCH=latest
PACKAGE_FETCH_BLACKLIST="$OWN_PACKAGES"
EOT
    mkdir -p "$DISTDIR"
    cat /usr/local/etc/poudriere.conf
    echo "::endgroup::"

    echo "::group::Create jail $JAIL (-v $FREEBSD_MAJOR -m pkgbase=$BASE_REPO)"
    poudriere jail -c -j "$JAIL" -v "$FREEBSD_MAJOR" -a amd64 \
        -m "pkgbase=$BASE_REPO" -U "$PKG_URL"
    poudriere jail -l
    echo "::endgroup::"

    echo "::group::Create ports trees"
    # shallow clones are poudriere's default (-D would fetch the full history)
    poudriere ports -c -p "$PTREE" -m git+https -U "$PORTS_REPO" -B "$PORTS_BRANCH"
    poudriere ports -c -p crowdsec -m git+https -U "$PACKAGING_REPO" -B "$PACKAGING_REF"
    poudriere ports -c -p pfsense -m null -M "$OVERLAY_DIR"
    poudriere ports -l
    echo "::endgroup::"

    echo "::group::Build amd64 packages"
    # a second pass reuses what was built and retries what failed: the go module
    # downloads (proxy.golang.org) occasionally fail with transient errors
    _bulk() {
        poudriere bulk -j "$JAIL" -p "$PTREE" -O crowdsec -O pfsense security/pfSense-pkg-crowdsec
    }
    _bulk || { echo "poudriere bulk failed, retrying once"; _bulk; }
    echo "::endgroup::"

    # All is a symlink to .latest/All (poudriere commits atomically)
    AMD64_PKGS="$BASEFS/data/packages/${JAIL}-${PTREE}/All"
    cs=$(find_pkg "$AMD64_PKGS" crowdsec)
    fw=$(find_pkg "$AMD64_PKGS" crowdsec-firewall-bouncer)
    pf=$(find_pkg "$AMD64_PKGS" pfSense-pkg-crowdsec)
    make_archive amd64 "FreeBSD:$FREEBSD_MAJOR:amd64" "$cs" "$fw" "$pf"
}

#
# arm64 / armv7: cross-compilation
#

# cross_build <arm64|armv7>
cross_build() {
    PORTS_DIR=$CROSS_BASE/ports
    CROWDSEC_PORTS_DIR=$CROSS_BASE/packaging

    echo "::group::[$1] Clone the ports trees"
    # host packages (go, pkgconf...) must come from the same branch as the ports tree
    mkdir -p /usr/local/etc/pkg/repos
    # shellcheck disable=SC2016 # ${ABI} is expanded by pkg
    echo 'FreeBSD: { url: "pkg+https://pkg.FreeBSD.org/${ABI}/latest", mirror_type: "srv" }' \
        > /usr/local/etc/pkg/repos/FreeBSD.conf
    pkg update -f
    mkdir -p "$DISTDIR"
    git clone --quiet --depth 1 --branch "$PORTS_BRANCH" "$PORTS_REPO" "$PORTS_DIR"
    git clone --quiet --depth 1 --branch "$PACKAGING_REF" "$PACKAGING_REPO" "$CROWDSEC_PORTS_DIR"
    git -C "$PORTS_DIR" log -1 --format='ports: %h %cd %s'
    git -C "$CROWDSEC_PORTS_DIR" log -1 --format='packaging-freebsd: %h %cd %s'
    echo "::endgroup::"

    case "$1" in
        # _binutils: host package providing a GNU ld.bfd for the target
        arm64) _arch=aarch64 _goarch=arm64 _binutils=aarch64-binutils
               _triple=aarch64-unknown-freebsd$FREEBSD_MAJOR.0 ;;
        armv7) _arch=armv7 _goarch=arm _binutils=arm-gnueabi-binutils
               _triple=armv7-unknown-freebsd$FREEBSD_MAJOR.0-gnueabihf ;;
        *) echo "unsupported architecture $1" >&2; return 1 ;;
    esac
    _abi=FreeBSD:$FREEBSD_MAJOR:$_arch
    _dir=$CROSS_BASE/$_arch
    _sysroot=$_dir/sysroot
    _keys=/usr/share/keys/cross-base
    mkdir -p "$_dir/repos" "$_dir/bin" "$_sysroot/var/db/pkg" "$_dir/packages/All"

    echo "::group::[$1] Install the $_abi sysroot from $BASE_REPO"
    # base repositories are signed either with the classic pkg key or with the
    # pkgbase-<major> keys (e.g. 15 aarch64): trust both. The directory is also
    # copied in the sysroot, in case pkg -r resolves it there.
    mkdir -p "$_keys/trusted" "$_keys/revoked"
    for _k in /usr/share/keys/pkg /usr/share/keys/pkgbase-*; do
        [ -d "$_k/trusted" ] && cp "$_k"/trusted/* "$_keys/trusted/"
    done
    ls "$_keys/trusted"
    mkdir -p "$_sysroot/usr/share/keys"
    cp -R "$_keys" "$_sysroot/usr/share/keys/"
    cat > "$_dir/repos/base.conf" <<EOT
base: {
  url: "$PKG_URL/$_abi/$BASE_REPO",
  mirror_type: "srv",
  signature_type: "fingerprints",
  fingerprints: "$_keys",
  enabled: yes
}
EOT
    _xpkg() {
        pkg -r "$_sysroot" -o ABI="$_abi" -o IGNORE_OSVERSION=yes \
            -o REPOS_DIR="$_dir/repos" -o PKG_CACHEDIR="$_dir/cache" "$@"
    }
    _xpkg update -f
    # the whole base, minus kernels, debug symbols, sources, tests and meta-packages
    _xpkg rquery -a '%n' \
        | grep -v -E -- '-(dbg|lib32|dbg-lib32|man|src|src-sys|tests)$|^FreeBSD-(kernel|set|src|tests)' \
        | sort > "$_dir/base.list"
    wc -l < "$_dir/base.list"
    # -I: no install scripts, they would be target binaries
    # shellcheck disable=SC2046
    _xpkg install -I $(cat "$_dir/base.list") > "$_dir/base-install.log" 2>&1 \
        || { tail -n 50 "$_dir/base-install.log" >&2; return 1; }
    test -f "$_sysroot/usr/include/sys/param.h" && test -x "$_sysroot/bin/sh"
    file "$_sysroot/bin/sh"
    echo "::endgroup::"

    echo "::group::[$1] Configure the cross toolchain ($_triple, GOARCH=$_goarch)"
    # Go links freebsd/arm64 with -fuse-ld=bfd, which the base system lacks:
    # use the GNU ld of the host's binutils package for the target, found by
    # clang through -B
    pkg install -y "$_binutils"
    # either <prefix>/<target>/bin/ld.bfd or <prefix>/bin/<target>-ld.bfd
    _bfd=$(pkg info -l "$_binutils" | grep -E '(/|-)ld\.bfd$' | head -n 1 | tr -d '[:space:]')
    test -x "$_bfd"
    ln -sf "$_bfd" "$_dir/bin/ld.bfd"
    "$_dir/bin/ld.bfd" --version | head -n 1
    # read by bsd.port.mk: ${LOCALBASE}/share/toolchains/${CROSS_TOOLCHAIN}.mk,
    # and ARCH is taken from the toolchain name (aarch64, armv7)
    mkdir -p /usr/local/share/toolchains
    cat > "/usr/local/share/toolchains/$_arch-clang.mk" <<EOT
XCC=	/usr/bin/cc --target=$_triple -B$_dir/bin
XCXX=	/usr/bin/c++ --target=$_triple -B$_dir/bin
XCPP=	/usr/bin/cpp --target=$_triple
CROSS_BINUTILS_PREFIX=	/usr/bin/
EOT
    cat > "$_dir/make.conf" <<EOT
CROSS_TOOLCHAIN=	$_arch-clang
CROSS_SYSROOT=	$_sysroot
OVERLAYS=	$CROWDSEC_PORTS_DIR
WRKDIRPREFIX=	$_dir/work
PACKAGES=	$_dir/packages
DISTDIR=	$DISTDIR
BATCH=	yes
# go.mk sets GOARM from ARCH, and passes CC (the cross compiler) to cgo
GO_ENV+=	GOARCH=$_goarch
EOT
    cat "/usr/local/share/toolchains/$_arch-clang.mk" "$_dir/make.conf"
    echo "::endgroup::"

    for _port in $CROSS_PORTS; do
        _portdir=$CROWDSEC_PORTS_DIR/$_port
        echo "::group::[$1] Build $_port"
        # build dependencies are host tools: install them natively
        make -C "$_portdir" PORTSDIR="$PORTS_DIR" OVERLAYS="$CROWDSEC_PORTS_DIR" \
            DISTDIR="$DISTDIR" BATCH=yes install-missing-packages
        make -C "$_portdir" PORTSDIR="$PORTS_DIR" __MAKE_CONF="$_dir/make.conf" \
            -V ARCH -V OSVERSION -V CC -V GO_ENV
        # the go module downloads (proxy.golang.org) occasionally fail with
        # transient errors: retry them before building
        _n=1
        until make -C "$_portdir" PORTSDIR="$PORTS_DIR" __MAKE_CONF="$_dir/make.conf" fetch \
                > "$LOGS_DIR/cross-$_arch-$(basename "$_port")-fetch.log" 2>&1; do
            tail -n 20 "$LOGS_DIR/cross-$_arch-$(basename "$_port")-fetch.log" >&2
            [ "$_n" -ge 3 ] && return 1
            _n=$((_n + 1))
            echo "fetch failed, attempt $_n/3 in 30s"
            sleep 30
        done
        make -C "$_portdir" PORTSDIR="$PORTS_DIR" __MAKE_CONF="$_dir/make.conf" package \
            > "$LOGS_DIR/cross-$_arch-$(basename "$_port").log" 2>&1 \
            || { tail -n 80 "$LOGS_DIR/cross-$_arch-$(basename "$_port").log" >&2; return 1; }
        tail -n 5 "$LOGS_DIR/cross-$_arch-$(basename "$_port").log"
        echo "::endgroup::"
    done

    _cs=$(find_pkg "$_dir/packages/All" crowdsec) || return 1
    _fw=$(find_pkg "$_dir/packages/All" crowdsec-firewall-bouncer) || return 1

    echo "::group::[$1] Build security/pfSense-pkg-crowdsec"
    # The ports framework records RUN_DEPENDS from the package database
    # (pkg query), and arm packages can't be installed on the amd64 host:
    # register them in the sysroot's database (-I: no install scripts) and
    # point pkg at it with PKG_DBDIR.
    # The package is NO_ARCH: Mk/Scripts/create-manifest.sh takes its ABI from
    # "pkg config abi", run without the ABI_FILE cross mode only gives to
    # pkg create, i.e. from the host (FreeBSD:15:* when building 16 on a 15.1
    # host). Export ABI_FILE so that it comes from the sysroot.
    _xpkg add -I -f "$_fw"
    _xpkg add -I -f "$_cs"
    _xpkg query '%n-%v %q' crowdsec crowdsec-firewall-bouncer
    ABI_FILE="$_sysroot/bin/sh" pkg config abi
    ABI_FILE="$_sysroot/bin/sh" PKG_DBDIR="$_sysroot/var/db/pkg" \
        make -C "$OVERLAY_DIR/security/pfSense-pkg-crowdsec" PORTSDIR="$PORTS_DIR" \
            __MAKE_CONF="$_dir/make.conf" package \
            > "$LOGS_DIR/cross-$_arch-pfSense-pkg-crowdsec.log" 2>&1 \
        || { tail -n 80 "$LOGS_DIR/cross-$_arch-pfSense-pkg-crowdsec.log" >&2; return 1; }
    tail -n 5 "$LOGS_DIR/cross-$_arch-pfSense-pkg-crowdsec.log"
    echo "::endgroup::"
    _pf=$(find_pkg "$_dir/packages/All" pfSense-pkg-crowdsec) || return 1

    make_archive "$_arch" "$_abi" "$_cs" "$_fw" "$_pf"
}

case "$TARGET" in
    amd64) build_amd64 ;;
    arm64|armv7) cross_build "$TARGET" ;;
    *) echo "Error: unknown target $TARGET" >&2; exit 1 ;;
esac

ls -l "$OUT_DIR"
