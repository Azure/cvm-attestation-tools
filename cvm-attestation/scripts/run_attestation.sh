# !/bin/bash

# Validate the exit status of previous execution
function check_exit_status() {
    exit_status=$?
    message=$1

    if [ $exit_status -ne 0 ]; then
        echo "$message: Failed (exit code: $exit_status)"
    else
        echo "$message: Succeeded"
    fi
}

function install_attestation_client() {
    attestation_repo_url="https://github.com/Azure/cvm-attestation-tools.git"
    git clone $attestation_repo_url >/dev/null 2>&1
    check_exit_status "Pull the code from repository $attestation_repo_url"
    
    cd cvm-attestation-tools/cvm-attestation

    # Update package lists
    echo "Updating package lists..."
    sudo apt-get -qq update -y
    check_exit_status "apt-get update"

    # Install tpm2-tools and Python
    echo "Installing tpm2-tools and Python..."
    sudo apt-get -qq install -y tpm2-tools python3 python3-pip
    check_exit_status "apt-get install tpm2-tools, python3, python3-pip"

    # Install Python packages
    echo "Installing Python requirements..."
    sudo -H pip3 install -q --upgrade pip
    check_exit_status "pip install --upgrade pip"

    sudo -H pip3 install -q -r requirements.txt
    check_exit_status "pip install -r requirements.txt"

    # Install CLI tool
    echo "Installing CLI tool..."
    sudo python3 setup.py install
    check_exit_status "python3 setup.py install"
}

install_attestation_client

group_id=$(dmesg | grep 'Isolation Config' | grep Group | awk '{print $NF}')
# TDX
if [[ $group_id == "0xbe3" ]]; then
    sudo attest  --c config_tdx.json
# SEV-SNP 
elif [[ $group_id == "0xba2" ]]; then
    sudo attest  --c config_snp.json
else
    echo "Unknown Group B ID: $group_id"
fi

exit 0