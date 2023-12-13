function Install-Chocolatey {
    Write-Output "Starting Install-Chocolatey..."

    $env:chocolateyVersion = '1.4.0'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    Write-Output "Starting Install-Chocolatey...Done"
}

function Install-Python {
    Write-Output "Starting Install-Python..."

    choco install -y python --version 3.10.2

    # Define the path you want to append
    $pythonPath = "C:\Python310"

    # Append the new path to the existing PATH variable
    $env:PATH += ";$pythonPath"

    python.exe -m pip install --upgrade pip
    python.exe -m pip install --upgrade setuptools
    python.exe -m pip install setuptools_scm
    python.exe -m pip install -r .\requirements.txt

    git submodule update --init --recursive

    Write-Output "Starting Install-Python...Done"
}


function run {
    Install-Chocolatey
    Install-Python

    # Install attest cli
    python.exe  setup.py install

     # Define the path you want to append
    $attestPath = "C:\Python310\Scripts"

    # Append the new path to the existing PATH variable
    $env:PATH += ";$attestPath"

}

if ((Resolve-Path -Path $MyInvocation.InvocationName).ProviderPath -eq $MyInvocation.MyCommand.Path) {
    run
}
