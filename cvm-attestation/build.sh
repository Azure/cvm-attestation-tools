#!/bin/bash
# Build script for CVM Attestation Tools
# Can be run locally or from GitHub Actions

set -e  # Exit on error

SKIP_INSTALL=false
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --skip-install)
      SKIP_INSTALL=true
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Color functions
write_step() {
    echo -e "\n\033[1;36m$1\033[0m"
}

write_success() {
    echo -e "\033[0;32m✓ $1\033[0m"
}

write_info() {
    echo -e "  \033[0;33m$1\033[0m"
}

echo -e "\033[1;36m=== CVM Attestation Tools - Build Script ===\033[0m"
write_info "Working directory: $(pwd)"

# Step 1: Install dependencies (unless skipped)
if [ "$SKIP_INSTALL" = false ]; then
    write_step "[1/6] Installing dependencies..."
    if [ -f "./install.sh" ]; then
        ./install.sh
        write_success "Dependencies installed"
    else
        echo "Warning: install.sh not found, skipping dependency installation"
    fi
else
    write_info "[1/6] Skipping dependency installation (--skip-install flag set)"
fi

# Detect Ubuntu version for pip compatibility
UBUNTU_VERSION=$(lsb_release -sr 2>/dev/null || echo "unknown")
if [[ "$UBUNTU_VERSION" == "24.04" ]]; then
    PIP_INSTALL_CMD="pip3 install --break-system-packages"
else
    PIP_INSTALL_CMD="pip3 install"
fi

# Step 2: Install PyInstaller
write_step "[2/6] Installing PyInstaller..."
$PIP_INSTALL_CMD pyinstaller --quiet --disable-pip-version-check
write_success "PyInstaller installed"

# Step 3: Build attest
write_step "[3/6] Building attest..."
python3 -m PyInstaller --onefile --distpath dist --clean ./attest.py
write_success "attest built successfully"

# Step 4: Build read_report
write_step "[4/6] Building read_report..."
python3 -m PyInstaller --onefile --distpath dist --clean ./read_report.py
write_success "read_report built successfully"

# Step 5: Copy configuration files
write_step "[5/6] Copying configuration files..."
cp *.json dist/
write_success "Configuration files copied"

# Step 6: Verify and prepare release
write_step "[6/6] Verifying and preparing release..."

# Verify executables exist
if [ ! -f "dist/attest" ]; then
    echo "ERROR: Executable not found: dist/attest"
    exit 1
fi
if [ ! -f "dist/read_report" ]; then
    echo "ERROR: Executable not found: dist/read_report"
    exit 1
fi

write_success "Both executables verified"

# Show dist contents
if [ "$VERBOSE" = true ]; then
    write_info "Contents of dist directory:"
    ls -lh dist/
fi

# Prepare clean release directory
rm -rf release
mkdir -p release

cp dist/attest release/
cp dist/read_report release/
cp *.json release/

write_success "Release directory prepared"

# Show release contents
write_info "Release directory contents:"
ls -lh release/

RELEASE_SIZE=$(du -sh release | cut -f1)
echo -e "\n\033[0;32m✅ BUILD SUCCESSFUL!\033[0m"
echo -e "\033[1;36mRelease package size: $RELEASE_SIZE\033[0m"
echo -e "\033[0;33mArtifacts available in: $(pwd)/release\033[0m"

exit 0
