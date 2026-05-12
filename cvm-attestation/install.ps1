function Install-Chocolatey {
    Write-Output "Starting Install-Chocolatey..."
    $env:chocolateyVersion = '1.4.0'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Write-Output "Install-Chocolatey...Done"
}

function Install-ModuleDependencies {
    Write-Output "Starting Install-ModuleDependencies..."
    python.exe -m pip install --upgrade pip
    python.exe -m pip install --upgrade setuptools
    python.exe -m pip install setuptools_scm build

    python.exe -m pip install -r .\requirements.txt

    git submodule update --init --recursive
    Write-Output "Install-ModuleDependencies...Done"
}

function Install-Python {
    Write-Output "Starting Install-Python..."
    choco install -y python --version 3.12.8

    $pythonPath = "C:\Python312"
    $env:PATH = "$pythonPath;" + $env:PATH

    Write-Output "Install-Python...Done"
}

function Build-And-Install {
    Write-Output "Building and Installing..."
    
    # Build the project
    python.exe -m build

    # Install the built wheel
    $wheel = Get-ChildItem -Path dist\*.whl | Select-Object -First 1
    if ($wheel) {
        python.exe -m pip install $wheel.FullName
    } else {
        Write-Error "Build failed: No .whl file found in dist/"
        exit 1
    }

    # Update PATH for attest CLI
    $attestPath = "C:\Python312\Scripts"
    $env:PATH = "$attestPath;" + $env:PATH

    Write-Output "Building and Installing...Done"
}

function Test-Python312Installed {
    try {
        $pythonVersion = python.exe --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $pythonVersion -match "Python 3\.12") {
            Write-Host "Python 3.12 is already installed: $pythonVersion"
            return $true
        }
    } catch {
        Write-Host "Python not found in PATH"
    }
    return $false
}

function run {
    $python312Installed = Test-Python312Installed

    if (-not $python312Installed) {
        Install-Chocolatey
        Install-Python
    } else {
        Write-Output "Skipping Chocolatey and Python installation..."
    }
    Install-ModuleDependencies
    Build-And-Install
}

if ((Resolve-Path -Path $MyInvocation.InvocationName).ProviderPath -eq $MyInvocation.MyCommand.Path) {
    run
}
