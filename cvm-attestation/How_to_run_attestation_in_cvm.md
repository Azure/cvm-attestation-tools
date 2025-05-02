# Attestation

Remote Attestation empowers a relying party, whether it be the workload owner or the user, to authenticate that their workload is operating on a platform equipped with Intel TDX or AMD SEV-SNP technology. This authentication should be done before providing sensitive information into the Guest workload. Currently, we support two forms of attestation: `platform` and `guest`, which are described below.


## 1. Install git to clone the required tools

### _Windows_
The following instructions are for Windows Confidential VMs.

#### Option 1: Download from the Official Website
Download Git from the official Git website:
[https://git-scm.com/downloads/win](https://git-scm.com/downloads/win)

> Once the executable is downloaded, follow the setup instructions provided by the installer.

#### Option 2: Download using winget
To download Git using the winget tool, follow these steps:

1. Ensure that the winget tool is installed on your system. If it is not installed, you can download it from the official Microsoft documentation: [Install winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget).
2. Open Command Prompt or PowerShell.
3. Run the following command to install Git:
  ```powershell
  winget install --id Git.Git -e --source winget
  ```
  ```

### _Linux_
The git tools should already be part of the Linux guest. To verify if git is installed, run the following command:

## 2. Install the Confidential VM Attestation Tools

### _Windows_
1. Open PowerShell as an administrator.
2. Clone the cvm-attestation-tools repository:
  ```powershell
  git clone https://github.com/Azure/cvm-attestation-tools.git
  ```
3. Navigate to the cvm-attestation folder:
  ```powershell
  cd cvm-attestation-tools/cvm-attestation/
  ```
4. Install the necessary dependencies by running the installation script:
  ```powershell
  .\install.ps1
  ```

#### Sample Output
After installing the dependencies, the output should look like the following:
```
> .\install.ps1
Starting Install-Chocolatey...
WARNING: 'choco' was found at 'C:\ProgramData\chocolatey\bin\choco.exe'.
WARNING: An existing Chocolatey installation was detected. Installation will not continue. This script will not
overwrite existing installations.

...

Installed c:\python310\lib\site-packages\attest-0.1-py3.10.egg
Processing dependencies for attest==0.1
Searching for click==8.1.8
Best match: click 8.1.8
Adding click 8.1.8 to easy-install.pth file

Using c:\python310\lib\site-packages
Searching for colorama==0.4.6
Best match: colorama 0.4.6
Adding colorama 0.4.6 to easy-install.pth file

Using c:\python310\lib\site-packages
Finished processing dependencies for attest==0.1
```
> **IMPORTANT NOTE:**
> - Ensure there are no errors during the installation process.
> - Verify that the tools are installed successfully by checking for the message `Finished processing dependencies for attest==0.1`.


### _Linux_
1. Open a terminal.
2. Clone the cvm-attestation-tools repository:
  ```bash
  git clone https://github.com/Azure/cvm-attestation-tools.git
  ```
3. Navigate to the cvm-attestation folder:
  ```bash
  cd cvm-attestation-tools/cvm-attestation/
  ```
4. Install the necessary dependencies by running the installation script:
  ```bash
  sudo ./install.sh
  ```

#### Sample Output
After installing the dependencies, the output should look like the following:

```
$ sudo ./install.sh
Updating package lists...
Hit:1 http://azure.archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://azure.archive.ubuntu.com/ubuntu jammy-updates InRelease [128 kB]
Hit:3 http://azure.archive.ubuntu.com/ubuntu jammy-backports InRelease
Get:4 http://azure.archive.ubuntu.com/ubuntu jammy-security InRelease [129 kB]
Fetched 257 kB in 1s (482 kB/s)
Reading package lists... Done
Installing tpm2-tools and Python...

...

Installed /usr/local/lib/python3.10/dist-packages/attest-0.1-py3.10.egg
Processing dependencies for attest==0.1
Searching for click==8.0.3
Best match: click 8.0.3
Adding click 8.0.3 to easy-install.pth file

Using /usr/lib/python3/dist-packages
Finished processing dependencies for attest==0.1
Installation completed successfully.
```
> **NOTE:**
>
> **Ensure there are no errors and verify that the tools are installed successfully by checking for the message `Finished processing dependencies for attest==0.1`.**

## 3. Running Attestation

### Guest Attestation
Guest attestation verifies that the CVM is running in either Intel TDX or AMD SEV-SNP hardware. Additionally, it verifies that the CVM is an `Azure CVM` by collecting hardware evidence (aka. hardware report and runtime data) and Guest OS measurements.

#### Linux
Run `guest attestation` using the following command:
```
sudo attest --c config_snp_guest.json --t guest
```

#### Windows
Run `guest attestation` using the following command:
```
attest --c config_snp_guest.json --t guest
```

#### Output
```
...
2025-02-07 18:38:02,714 - print_guest_claims - INFO - Claims:
2025-02-07 18:38:02,714 - print_guest_claims - INFO - Attestation Type: sevsnpvm
2025-02-07 18:38:02,714 - print_guest_claims - INFO - Status: azure-compliant-cvm
2025-02-07 18:38:02,714 - print_guest_claims - INFO - SNP Bootloader SVN: 4
2025-02-07 18:38:02,714 - print_guest_claims - INFO - SNP Guest SVN: 8
2025-02-07 18:38:02,714 - print_guest_claims - INFO - SNP Microcode SVN: 211
2025-02-07 18:38:02,714 - print_guest_claims - INFO - SNP Firmware SVN: 21
2025-02-07 18:38:02,714 - print_guest_claims - INFO - SNP TEE SVN: 0
2025-02-07 18:38:02,714 - print_guest_claims - INFO - Report Data: 88776aba87d799e94c8c8d4c318339e0c2867ee8a289261b21c1e3af614f29de0000000000000000000000000000000000000000000000000000000000000000
2025-02-07 18:38:02,714 - print_guest_claims - INFO - User Claims Digest: 4BD03DC197F0BF46D4D40480925401BE4FC55D6EFD05095D867EBA038F4432BB0F2EA7F0D8AAE01811044038FE61ED662866C7E67A5482CD94DB0069B67717AE
2025-02-07 18:38:02,714 - print_guest_claims - INFO - Attested Guest Successfully!!
```

### Platform Attestation
Platform attestation verifies that the CVM is running in an Intel TDX or AMD SEV-SNP hardware.

#### Linux
Run `platform attestation` using the following command:
```
sudo attest --c config_snp.json
```

#### Windows
Run `platform attestation` using the following command:
```
attest --c config_snp.json
```

> **IMPORTANT**
>
> **To run `Platform Attestation` on TDX, use the `config_tdx.json` for MAA or `config_tdx_ita.json` for Intel's Trust Authority.**

#### Output
```
...
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - Claims:
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - Attestation Type: sevsnpvm
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - Status: azure-compliant-cvm
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - SNP Bootloader SVN: 4
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - SNP Guest SVN: 8
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - SNP Microcode SVN: 211
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - SNP Firmware SVN: 21
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - SNP TEE SVN: 0
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - Report Data: 88776aba87d799e94c8c8d4c318339e0c2867ee8a289261b21c1e3af614f29de0000000000000000000000000000000000000000000000000000000000000000
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - User Claims: 4BD03DC197F0BF46D4D40480925401BE4FC55D6EFD05095D867EBA038F4432BB0F2EA7F0D8AAE01811044038FE61ED662866C7E67A5482CD94DB0069B67717AE
2025-02-07 18:13:00,408 - print_snp_platform_claims - INFO - Attested Platform Successfully!!
```

## 4. Verify the Results
After running the sample app, we should see the message one of the following messages `Attested Platform Successfully!!` or `Attested Guest Successfully!!`. This means that the attestation provider was able to verify the information successfully and a token is returned.

### Verifying User Claims
To check that the unique claims provided are inscribed into the hardware report, check that the user claim hash matches the `user-claims` hash digest returned during attestation.

#### How to specify unique user claims
To add your own unique user claims that will be imprinted into the hardware report, add any json object into the `claims` config json file.

##### Claims Example
```
"claims": {
        "user-claims": {
            "nonce": "Hello This Was Generated By Javier"
        }
    }
```


#### User provided claims
From the configuration file we can read the `claims` object, then take the SHA512 of the entire JSON object, and pass it to the attestation tool to include it in the hardware report. In the logs, we can check this value which is printed before attestation is performed.
```
2025-02-07 18:37:59,195 - attest - INFO - claims: {'user-claims': {'nonce': 'Hello This Was Generated By Javier'}}
2025-02-07 18:37:59,196 - attest - INFO - SHA512 of user provided claims: 4BD03DC197F0BF46D4D40480925401BE4FC55D6EFD05095D867EBA038F4432BB0F2EA7F0D8AAE01811044038FE61ED662866C7E67A5482CD94DB0069B67717AE
```

#### Claims in the `Hardware Report`
```
2025-02-07 18:38:02,714 - print_guest_claims - INFO - User Claims Digest: 4BD03DC197F0BF46D4D40480925401BE4FC55D6EFD05095D867EBA038F4432BB0F2EA7F0D8AAE01811044038FE61ED662866C7E67A5482CD94DB0069B67717AE
```

> **IMPORTANT**
> 
> Both claims from the logs above should match.
To check all the fields returned by the attestation provider in the token, use the following steps.

1. Look for the token in the logs
```
2025-02-07 18:38:02,713 - attest_guest - INFO - TOKEN:
Token will be printed below>
```
2. Use any of the JSON web token decoder
    - [jwt.ms](https://jwt.ms/)
    - [jwt.io](https://jwt.io/)
3. Copy the Token to the jwt decoder

**JWT Fields Example:**
```
...
  "exp": 1738982052,
  "iat": 1738953252,
  "iss": "https://sharedweu.weu.attest.azure.net",
  "jti": "f0ee3770c786584011b1b2e3879277f44063a5d30204a3fcefd0b798e62ed7b0",
  "nbf": 1738953252,
  "secureboot": true,
  "x-ms-attestation-type": "azurevm",
  "x-ms-azurevm-attestation-protocol-ver": "2.0",
...
```