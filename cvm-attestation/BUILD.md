# Building CVM Attestation Tools

## Quick Start

### Windows
```powershell
.\build.ps1
```

### Linux
```bash
chmod +x build.sh
./build.sh
```

## Build Options

### Skip dependency installation (faster if already installed)
```powershell
# Windows
.\build.ps1 -SkipInstall

# Linux  
./build.sh --skip-install
```

### Verbose output
```powershell
# Windows
.\build.ps1 -Verbose

# Linux
./build.sh --verbose
```

## What Gets Built

The build script creates:
- `attest.exe` / `attest` - Main attestation CLI tool
- `read_report.exe` / `read_report` - Report parsing CLI tool
- `release/` directory with executables + configuration files (~16MB)

## First Time Setup

Run the install script once before building:

```powershell
# Windows (requires admin)
.\install.ps1
```

```bash
# Linux
./install.sh
```

After that, use `build.ps1` or `build.sh` with the `-SkipInstall` flag for faster builds.

## GitHub Actions

The same build scripts are used in CI/CD, ensuring consistency between local and remote builds.
