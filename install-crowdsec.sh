#!/bin/sh

set -eu

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

terminate_orphans() {
    PROC_NAMES="crowdsec notification-email notification-http notification-sentinel notification-slack notification-splunk"
    ORPHAN_PIDS=""

    echo "Checking for orphan processes..."

    for PROC_NAME in $PROC_NAMES; do
        PIDS=$(pgrep -x "$PROC_NAME" || :)

        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                PROCESS_INFO=$(ps -p "$PID" -o pid,comm | tail -n +2)
                echo "Found process: $PROCESS_INFO"
                ORPHAN_PIDS="$ORPHAN_PIDS $PID"
            done
        fi
    done

    if [ -n "$ORPHAN_PIDS" ]; then
        echo "Terminating processes: $ORPHAN_PIDS"
        # shellcheck disable=SC2086
        kill -9 $ORPHAN_PIDS || :
        echo "done."
    else
        echo "No orphan process found."
    fi
}


terminate_services() {
    echo "Stopping crowdsec services..."
    PID_FILES="/var/run/crowdsec_daemon.pid /var/run/crowdsec.pid /var/run/crowdsec_firewall.pid"
    for pidfile in $PID_FILES; do
        if [ -f "$pidfile" ]; then
            PID=$(cat "$pidfile")
            if kill -0 "$PID" > /dev/null 2>&1; then
                # don't use TERM, to make sure sbin/daemon doesn't hang if crowdsec is misconfigured
                kill -INT "$PID" || true
            else
                echo "Process $PID (from $pidfile) is not running."
            fi
        fi
    done

    service crowdsec onestop || true
    service crowdsec_firewall onestop || true
    terminate_orphans
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
        echo
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

    echo
    echo "The archive to be downloaded is: $ASSET_URL"

    echo
    printf "Do you want to proceed with the download? (y/N) "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Download canceled."
        exit 1
    fi

    echo "Downloading archive: $ASSET_URL"
    echo "done."

    download "$ASSET_URL" > "$TARFILE"
}


install_packages() {
    if ! command -v pkg > /dev/null; then
        echo
        echo "Error: The 'pkg' command is not available on this system."
        echo "Please manually install the packages using 'pkg add -f' on a pfSense system, or run this script there."
        exit 1
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo
        echo "This script must be run as root. Please run it as root or manually install the packages."
        exit 1
    fi

    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    echo "Extracting archive to $TMP_DIR"
    tar -xzf "$TARFILE" -C "$TMP_DIR"

    # Install the packages in order to respect the dependencies
    PKG_NAMES="abseil re2 crowdsec-firewall-bouncer crowdsec pfSense-pkg-crowdsec"

    echo
    echo "The following packages are ready for installation:"

    PKG_PATHS=""
    for package in $PKG_NAMES; do
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
    printf "Do you want to install them now? (y/N) "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Installation canceled."
        exit 1
    fi

    terminate_services

    # prevent the services from starting before the plugin configures the filter tables
    rm -f /var/run/crowdsec.running /var/run/crowdsec_firewall.running

    for PKG_PATH in $PKG_PATHS; do
        echo "Installing $(basename "$PKG_PATH")"
        pkg add -qf "$PKG_PATH"
        sleep 3
    done

    # Clean up
    rm -rf "$TMP_DIR"

    echo "# -------------- #"
    echo "Installation complete."
    echo "You can configure and activate CrowdSec on you pfSense admin page (Package / Services: CrowdSec)."
}


uninstall_packages() {
    if [ "$(uname -s)" != "FreeBSD" ]; then
        echo "Error: The --uninstall option is intended for FreeBSD systems."
        exit 1
    fi

    if [ "$(id -u)" -ne 0 ]; then
        echo
        echo "This script must be run as root to uninstall the packages."
        exit 1
    fi

    # Uninstall the packages in order of dependency
    PKG_NAMES="pfSense-pkg-crowdsec crowdsec-firewall-bouncer crowdsec"
    INSTALLED_PKGS=""

    echo "Checking for installed CrowdSec-related packages..."
    for package in $PKG_NAMES; do
        if pkg info "$package" > /dev/null 2>&1; then
            PKG_VERSION=$(pkg info "$package" | grep Version | awk '{print $3}')
            echo " - $package (version $PKG_VERSION) is installed."
            INSTALLED_PKGS="$INSTALLED_PKGS $package"
        fi
    done

    if [ -z "$INSTALLED_PKGS" ]; then
        echo "No CrowdSec-related packages are installed."
        exit 0
    fi

    echo
    printf "Do you want to uninstall these packages? (y/N) "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Uninstallation canceled."
        exit 1
    fi

    # In case the service management is not behaving correctly, stop the services manually
    terminate_services

    echo "Uninstalling packages..."
    for package in $INSTALLED_PKGS; do
        echo "Removing $package..."
        pkg delete -y "$package"
    done

    echo "Uninstallation complete."
    echo "Configuration and data are left in /usr/local/etc/crowdsec and /var/db/crowdsec,"
    echo "in case you want to reinstall or upgrade CrowdSec."

    rm -f /var/run/crowdsec.running /var/run/crowdsec_firewall.running
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
        --uninstall)
            uninstall_packages
            shift
            exit 0
            ;;
        *)
            echo "Usage: $0 [--release <version>] [--arch <architecture>] [--freebsd <version>] | [--from <tarfile>]"
            exit 1
            ;;
    esac
    shift
done

echo "#----------------------------------------------------------------#"
echo "# This script is intended to be used only if the CrowdSec        #"
echo "# package is not available in the official pfSense repositories, #"
echo "# or to test pre-release versions.                               #"
echo "# Please check the pfSense package manager before proceeding.    #"
echo "#----------------------------------------------------------------#"
echo

# Prompt user for confirmation to proceed
printf "Do you want to continue? (y/N) "
read -r REPLY
if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
    echo "Operation canceled."
    exit 1
fi

echo

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
