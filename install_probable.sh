#!/bin/bash

set -e  # Exit immediately if any command fails

# Ensure the script is run with Bash
if [ -z "$BASH_VERSION" ]; then
    exec bash "$0" "$@"
fi

# Function to retry commands up to 5 times, showing output live
retry_command() {
    local n=1
    local max=5
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                echo "⚠️ Command failed. Retrying attempt $n/$max..."
                sleep $delay;
            else
                echo "❌ The command has failed after $n attempts."
                exit 1
            fi
        }
    done
}

# Update package lists
echo "🔄 Updating package lists..."
retry_command sudo apt-get update -y

# Install required system dependencies
echo "📦 Installing required system packages..."
retry_command sudo apt-get install -y tpm2-tools python3 python3-pip python3-venv python3-setuptools python3-wheel build-essential libssl-dev libffi-dev python3-dev

# Define virtual environment path
VENV_PATH="./cvm-attestation"

# Create and activate a virtual environment
if [ ! -d "$VENV_PATH" ]; then
    echo "🛠 Creating virtual environment at $VENV_PATH..."
    retry_command sudo python3 -m venv "$VENV_PATH"
fi
source "$VENV_PATH/bin/activate"

# Upgrade pip, setuptools, and wheel inside the virtual environment
echo "⬆️ Upgrading pip, setuptools, and wheel..."
retry_command pip install --upgrade pip setuptools wheel

# Install Python requirements inside the virtual environment
if [ -f "requirements.txt" ]; then
    echo "📜 Installing Python dependencies from requirements.txt..."
    retry_command pip install -r requirements.txt
else
    echo "⚠️ Warning: requirements.txt not found. Skipping dependency installation."
fi

# Check if pipx is available, otherwise install it
if ! command -v pipx &>/dev/null; then
    echo "🔧 pipx not found, installing..."
    retry_command sudo apt-get install -y pipx
    retry_command pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
fi

# Install CLI tools system-wide using pipx
echo "🚀 Installing CLI tools globally with pipx..."
retry_command pipx install .

# Verify installation
echo "✅ Verifying installation..."
for tool in attest read_report; do
    if command -v "$tool" &>/dev/null; then
        echo "✅ '$tool' is installed and ready to use!"
    else
        echo "❌ Installation failed: '$tool' not found!"
        exit 1
    fi
done

echo "🎉 Installation completed successfully!"
echo "💡 You can now run CLI tools like 'attest' and 'read_report' from anywhere."
