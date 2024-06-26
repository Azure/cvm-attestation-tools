#!/bin/bash

set -e

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
retry_command sudo apt-get install -y tpm2-tools python3 python3-pip

# Install Python packages
echo "Installing Python requirements..."
retry_command sudo -H pip3 install --upgrade pip
retry_command sudo -H pip3 install -r requirements.txt

# Install CLI tool
echo "Installing CLI tool..."
retry_command sudo python3 setup.py install

echo "Installation completed successfully."
