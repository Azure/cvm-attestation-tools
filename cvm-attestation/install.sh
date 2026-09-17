#!/bin/bash

set -e

#
# Run apt non-interactively.
#
# `sudo` resets the environment (env_reset in sudoers), so exporting
# DEBIAN_FRONTEND / NEEDRESTART_MODE in this script does not reach apt-get.
# Without them, Ubuntu 22.04+ shows the needrestart "Which services should be
# restarted?" whiptail dialog, which blocks forever on stdin when this script
# runs from automation (no TTY).
#
apt_get() {
    sudo env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        apt-get -y -o Dpkg::Options::=--force-confold "$@"
}

# Function to check if a command succeeded and retry up to 5 times if it fails
retry_command() {
    local n=1
    local max=5
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                echo "Command failed. Attempt $n/$max:"
                sleep $delay;
            else
                echo "The command has failed after $n attempts."
                exit 1
            fi
        }
    done
}

# Update package lists
echo "Updating package lists..."
retry_command sudo apt-get update

# Install tpm2-tools and Python
echo "Installing tpm2-tools and Python..."
retry_command apt_get install tpm2-tools python3 python3-pip

# Detect Ubuntu version
UBUNTU_VERSION=$(lsb_release -sr)

#
# Set pip install command based on Ubuntu version.
# Ubuntu 24.04 and later mark the system Python as externally managed (PEP 668),
# so pip refuses system-wide installs and cannot upgrade the debian-packaged pip.
# ERROR: Cannot uninstall pip 24.0, RECORD file not found. Hint: The package was installed by debian.
#
# TODO: Remove this conditional by packaging the tool using a virtual environment or pipx solution.
#
if [[ "$(printf '%s\n24.04\n' "$UBUNTU_VERSION" | sort -V | head -n1)" == "24.04" ]]; then
    PIP_INSTALL_CMD="sudo -H pip3 install --break-system-packages"
else
    PIP_INSTALL_CMD="sudo -H pip3 install"
    retry_command $PIP_INSTALL_CMD --upgrade pip
fi

# Install Python packages
echo "Installing Python requirements using $PIP_INSTALL_CMD..."
retry_command $PIP_INSTALL_CMD -r requirements.txt

# Install CLI tool
echo "Installing CLI tool..."
retry_command $PIP_INSTALL_CMD .

echo "Installation completed successfully."
