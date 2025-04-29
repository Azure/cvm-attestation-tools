function Install-Chocolatey {
    Write-Output "Starting Install-Chocolatey..."
    $env:chocolateyVersion = '1.4.0'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Set-ExecutionPolicy Bypass -Scope Process -Force
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Write-Output "Install-Chocolatey...Done"
}

function Install-Python {
    Write-Output "Starting Install-Python..."
    choco install -y python --version 3.10.2

    $pythonPath = "C:\Python310"
    $env:PATH += ";$pythonPath"

    python.exe -m pip install --upgrade pip
    python.exe -m pip install --upgrade setuptools
    python.exe -m pip install setuptools_scm build

    python.exe -m pip install -r .\requirements.txt

    git submodule update --init --recursive
    Write-Output "Install-Python...Done"
}

function Build-And-Install {
    Write-Output "Building and Installing..."
    
    # Build the project
    python.exe -m build

    # Install the built wheel
    $wheel = Get-ChildItem -Path dist\*.whl | Select-Object -First 1
    if ($wheel) {
        pip install $wheel.FullName
    } else {
        Write-Error "Build failed: No .whl file found in dist/"
        exit 1
    }

    # Update PATH for attest CLI
    $attestPath = "C:\Python310\Scripts"
    $env:PATH += ";$attestPath"

    Write-Output "Building and Installing...Done"
}

function run {
    Install-Chocolatey
    Install-Python
    Build-And-Install
}

if ((Resolve-Path -Path $MyInvocation.InvocationName).ProviderPath -eq $MyInvocation.MyCommand.Path) {
    run
}
