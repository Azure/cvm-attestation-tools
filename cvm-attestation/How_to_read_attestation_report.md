# Reading the TCB Version from SNP Attestation Report

This document provides a detailed guide on how to retrieve the Trusted Computing Base (TCB) version from an AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) Confidential VM. The TCB version is crucial for verifying the security and integrity of the virtual machine environment. Follow the steps outlined below to accurately collect and interpret the TCB version information.

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

### _Linux_
The git tools should already be part of the Linux guest

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
> **NOTE:** Ensure there are no errors and verify that the tools are installed successfully by checking for the message `Finished processing dependencies for attest==0.1`.


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
> **NOTE:** Ensure there are no errors and verify that the tools are installed successfully by checking for the message `Finished processing dependencies for attest==0.1`.

## 3. Retrieving the SNP Attestation Report

### _Windows_
To retrieve the attestation report, run the following command:
  ```powershell
  .\read_report.ps1
  ```
  > **NOTE:** Ensure you run PowerShell as an administrator because the tool requires elevated privileges to access the Virtual TPM.

### _Linux_
To retrieve the attestation report, run the following command:
  ```bash
  sudo ./read_report.sh
  ```
  > **NOTE:** We use `sudo` to run the script with root privileges because the tool requires elevated permissions to access the Virtual TPM.


#### Sample Output
The output sample is a detailed log of the attestation process for a hardware report.

```
SHELL> read_report
TSS.Py::__INIT__.PY invoked
2025-01-24 19:16:01,001 - read_report - INFO - Attestation started...
2025-01-24 19:16:01,001 - read_report - INFO - Report type selected: snp_report
2025-01-24 19:16:01,001 - handle_hardware_report - INFO - Reading hardware report: snp_report
2025-01-24 19:16:01,001 - get_hardware_report - INFO - Parsing hardware report...
2025-01-24 19:16:01,001 - get_hcl_report - INFO - Getting hcl report from vTPM...
2025-01-24 19:16:01,480 - get_hcl_report - INFO - Got HCL Report from vTPM!
2025-01-24 19:16:01,480 - log_snp_report - INFO - Attestation report size: 1184 bytes
2025-01-24 19:16:01,485 - log_snp_report - INFO - Report version: 2
2025-01-24 19:16:01,485 - log_snp_report - INFO - Report guest svn: 7
2025-01-24 19:16:01,485 - log_snp_report - INFO - Current TCB version: DB16000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Reported TCB version: D315000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Committed TCB version: D515000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Launched TCB version: D515000000000004
Attestation Report (1184 bytes):
Version:                      2
Guest SVN:                    7

Guest Policy (0x3001f):
    ABI Major:     0
    ABI Minor:     31
    SMT Allowed:   1
    Migrate MA:    0
    Debug Allowed: 0
    Single Socket: 0

Family ID:
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Image ID:
02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

VMPL:                         0
Signature Algorithm:          1

Current TCB: DB16000000000004
  Microcode:   219
  SNP:         22
  TEE:         0
  Boot Loader: 4

...

2025-01-24 19:16:01,594 - handle_hardware_report - INFO - Report saved to: report.bin
2025-01-24 19:16:01,594 - handle_hardware_report - INFO - Got attestation report successfully!
```

### 4. Reading TCB Version
The output in the above step displays the different TCB versions in HEX format (Big Endian) as well as in a human-readable format.

#### Breakdown Example
```
Current TCB: DB16000000000004
  Microcode:   219
  SNP:         22
  TEE:         0
  Boot Loader: 4
```

#### Different TCB versions from Logs
The logs provide various TCB versions, each representing a different state of the Trusted Computing Base. Below is an example of how these versions are logged:
- **Current TCB version**: The TCB version currently in use.
- **Reported TCB version**: The TCB version reported by the attestation report.
- **Committed TCB version**: The TCB version that has been committed.
- **Launched TCB version**: The TCB version at the time of the VM launch.

These versions help in understanding the security posture and the integrity of the virtual machine environment.
```
2025-01-24 19:16:01,485 - log_snp_report - INFO - Current TCB version: DB16000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Reported TCB version: D315000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Committed TCB version: D515000000000004
2025-01-24 19:16:01,485 - log_snp_report - INFO - Launched TCB version: D515000000000004
```
> By comparing these versions, we can verify that the TCB of the machine running the CVM aligns with AMD's released versions.
