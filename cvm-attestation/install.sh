#!/bin/bash

set -e

# Function to check if a command succeeded
check_command_success() {
    if [ $? -ne 0 ]; then
        echo "Error executing command: $1"
        exit 1
    fi
}

# Update package lists
echo "Updating package lists..."
sudo apt-get update
check_command_success "apt-get update"

# Install tpm2-tools and Python
echo "Installing tpm2-tools and Python..."
sudo apt-get install -y tpm2-tools python3 python3-pip
check_command_success "apt-get install tpm2-tools, python3, python3-pip"

# Install Python packages
echo "Installing Python requirements..."
sudo -H pip3 install --upgrade pip
check_command_success "pip install --upgrade pip"
sudo -H pip3 install -r requirements.txt
check_command_success "pip install -r requirements.txt"

# Install CLI tool
echo "Installing CLI tool..."
sudo python3 setup.py install
check_command_success "python3 setup.py install"

echo "Installation completed successfully."
