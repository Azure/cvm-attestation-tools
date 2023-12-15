function Install-Chocolatey {
    Write-Output "Starting Install-Chocolatey..."

    $env:chocolateyVersion = '1.4.0'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    Write-Output "Starting Install-Chocolatey...Done"
}

function Install-Git {
    choco install -y git
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Output "Install-Git...Done"
}

function Install-Python {
    Write-Output "Starting Install-Python..."

    choco install -y python --version 3.10.2

    # Define the path you want to append
    $pythonPath = "C:\Python310"

    # Append the new path to the existing PATH variable
    $env:PATH += ";$pythonPath"

    python.exe -m pip install --upgrade pip

    Write-Output "Starting Install-Python...Done"
}

function Install-AttestationApp {
    git clone https://github.com/Azure/cvm-attestation-tools.git
    pushd .\cvm-attestation-tools\cvm-attestation\
    # Install attest cli
    python.exe -m pip install -r .\requirements.txt
    python.exe setup.py install
    
     # Define the path you want to append
    $attestPath = "C:\Python310\Scripts"

    # Append the new path to the existing PATH variable
    $env:PATH += ";$attestPath"
}

try {
    Install-Chocolatey
    Install-Git
    Install-Python
    Install-AttestationApp

    # Check if it's SEV-SNP (AMD) or TDX (Intel)
    $output = & reg.exe query HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
    $vendor = ""
    foreach ($line in $output) {
        if ($line -imatch "VendorIdentifier") {
            $vendor = $line.Trim().Split(" ")[-1]
            break
        }
    }
    if ($vendor -eq "AuthenticAMD") {
        attest.exe --c .\config_snp.json
    } elseif ($vendor -eq "GenuineIntel") {
        attest.exe --c .\config_tdx.json
    } else {
        Write-Output "Unknown hardware vendor: $vendor"
    }
} catch {
    $line = $_.InvocationInfo.ScriptLineNumber
    $scriptName = $_.InvocationInfo.ScriptName
    $errorMessage = $_.Exception.Message
    Write-Output "EXCEPTION : $errorMessage"
    Write-Output "Source : Line $line in script $scriptName."
}
exit 0