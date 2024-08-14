#!/bin/sh

set -e


# Allow downloading on other systems too
download() {
    if command -v fetch > /dev/null; then
        fetch -q -o - "$1"
    elif command -v curl > /dev/null; then
        curl -fsSL "$1"
    elif command -v wget > /dev/null; then
        wget --no-verbose -O- "$1"
    else
        echo "Error: No suitable download tool found. Please install fetch, wget, or curl."
        exit 1
    fi
}


# Set variables used by get_archive
set_vars() {
    REPO_OWNER="crowdsecurity"
    REPO_NAME="pfSense-pkg-crowdsec"

    # Fetch the latest stable release, unless a specific tag is requested
    RELEASE_TYPE="latest"

    if [ "$(uname -s)" = "FreeBSD" ]; then
        DETECTED_ARCH=$(uname -m)
        DETECTED_FREEBSD_VERSION=$(uname -r | cut -d- -f1 | cut -d. -f1)
    else
        DETECTED_ARCH=
        DETECTED_FREEBSD_VERSION=
    fi

    if [ -z "$ARCH" ]; then
        ARCH="$DETECTED_ARCH"
    fi

    if [ -z "$FREEBSD_VERSION" ]; then
        FREEBSD_VERSION="$DETECTED_FREEBSD_VERSION"
    fi

    if [ -z "$ARCH" ] || [ -z "$FREEBSD_VERSION" ]; then
        echo "Error: This script is intended for FreeBSD systems."
        echo "Please specify both --arch and --freebsd parameters to continue."
        echo "Example: $0 --arch amd64 --freebsd 15"
        exit 1
    fi

    if [ "$(uname -i)" != "pfSense" ]; then
        echo "Warning: This script is intended for pfSense systems."
        echo "If this is not the case you will be able to download the packages, but you may not be able to use them."
    fi

    if [ -n "$RELEASE_TAG" ]; then
        RELEASE_TYPE="tags/$RELEASE_TAG"
    fi

}


# download the required archive and set the $TARFILE variable
get_archive() {
    URL="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/$RELEASE_TYPE"
    echo "Looking up $URL"

    # Fetch the release data from GitHub API
    RELEASE_JSON=$(download "$URL")

    TARFILE="freebsd-$FREEBSD_VERSION-$ARCH.tar"

    echo "Selecting archive for FreeBSD $FREEBSD_VERSION/$ARCH"

    # We have jq at home
    ASSET_URL=$(echo "$RELEASE_JSON" | tr ',' '\n' | grep '"browser_download_url":' | grep "/$TARFILE" | sed -E 's/.*"browser_download_url": *"([^"]+)".*/\1/')

    if [ -z "$ASSET_URL" ]; then
        echo "Error: Can't find file $TARFILE in the release assets."
        exit 1
    fi

    echo "Downloading archive: $ASSET_URL to $TARFILE"

    download "$ASSET_URL" > "$TARFILE"
}


install_packages() {
    if ! command -v pkg > /dev/null; then
        echo "Error: The 'pkg' command is not available on this system."
        echo "Please manually install the packages using 'pkg add -f' on a pfSense system, or run this script there."
        exit 1
    fi

    TMP_DIR=$(mktemp -d)

    echo "Extracting archive to $TMP_DIR"
    tar -xzf "$TARFILE" -C "$TMP_DIR"

    # Install the packages in order to respect the dependencies
    PKG_FILES="abseil re2 crowdsec-firewall-bouncer crowdsec pfSense-pkg-crowdsec"

    echo
    echo "The following packages will be installed:"

    PKG_PATHS=""
    for package in $PKG_FILES; do
        # match a digit from the version to avoid matching other packages too
        PKG_PATH=$(find "$TMP_DIR" -name "$package-[0-9]*.pkg")
        if [ -n "$PKG_PATH" ]; then
            echo " - $(basename "$PKG_PATH")"
            PKG_PATHS="$PKG_PATHS $PKG_PATH"
        else
            echo "Error: Package $package not found in the archive."
            exit 1
        fi
    done

    echo
    printf "Do you want to continue with the installation? (y/N) "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Installation aborted."
        exit 1
    fi

    echo "Stopping crowdsec service..."
    # make sure sbin/daemon doesn't hang if crowdsec is misconfigured (TERM -> INT)
    for pidfile in /var/run/crowdsec_daemon.pid /var/run/crowdsec.pid /var/run/crowdsec_firewall.pid; do
        if [ -f "$pidfile" ]; then
            kill -INT "$(cat "$pidfile")" || true
        fi
    done

    for PKG_PATH in $PKG_PATHS; do
        echo "Installing $(basename "$PKG_PATH")"
        pkg add -qf "$PKG_PATH"
    done

    # Clean up
    rm -rf "$TMP_DIR"

    echo "# -------------- #"
    echo "Installation complete."
    echo "You can configure and activate CrowdSec on you pfSense admin page (Package / Services: CrowdSec)."
}

# -------------- #

RELEASE_TAG=""
ARCH=""
FREEBSD_VERSION=""
TARFILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --release)
            RELEASE_TAG="$2"
            shift
            ;;
        --arch)
            ARCH="$2"
            shift
            ;;
        --freebsd)
            FREEBSD_VERSION="$2"
            shift
            ;;
        --from)
            TARFILE="$2"
            shift
            ;;
        *)
            echo "Usage: $0 [--release <version>] [--arch <architecture>] [--freebsd <version>] | [--from <tarfile>]"
            exit 1
            ;;
    esac
    shift
done

if [ -n "$TARFILE" ]; then
    if [ -n "$RELEASE_TAG" ] || [ -n "$ARCH" ] || [ -n "$FREEBSD_VERSION" ]; then
        echo "Error: When using --from an existing archive, you can't select release, architecture or freebsd version."
        exit 1
    fi
    if [ ! -f "$TARFILE" ]; then
        echo "Error: Specified tar file $TARFILE does not exist."
        exit 1
    fi
    echo "Using provided tar file: $TARFILE"
else
    set_vars
    get_archive
fi

install_packages
