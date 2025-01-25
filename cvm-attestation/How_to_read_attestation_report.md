# Reading the SNP TCB Version from Attestation Report

This document provides a detailed guide on how to retrieve the Trusted Computing Base (TCB) version from an AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP) CVM. The TCB version is crucial for verifying the security and integrity of the virtual machine environment. Follow the steps outlined below to accurately collect and interpret the TCB version information.

# Windows
The following instructions are for Windows CVMs.

## Prerequisites
Ensure that Git is installed on your system before proceeding with the following steps.

### Option 1: Download from the Official Website
Download Git from the official Git website:
[https://git-scm.com/downloads/win](https://git-scm.com/downloads/win)

> Once the executable is downloaded, follow the setup instructions provided by the installer.

### Option 2: Download using winget

To download Git using the winget tool, follow these steps:

1. Ensure that the winget tool is installed on your system. If it is not installed, you can download it from the official Microsoft documentation: [Install winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget).
2. Open Command Prompt or PowerShell.
3. Run the following command to install Git:
  ```powershell
  winget install --id Git.Git -e --source winget
  ```


## Installing the CVM Attestation Tools
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
5. To retrieve the attestation report, run the following command:
  ```powershell
  .\read_report.ps1
  ```
  > **NOTE:** Ensure you run PowerShell as an administrator because the tool requires elevated privileges to access the Virtual TPM.


# Linux
The following instructions are for CVMs running Linux.

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
5. To retrieve the attestation report, run the following command:
  ```bash
  sudo ./read_report.sh
  ```
  > **NOTE:** We use `sudo` to run the script with root privileges because the tool requires elevated permissions to access the Virtual TPM.

## Reading TCB Version
This tool displays the different TCB versions in HEX format (Big Endian) as well as in a human-readable format.

### Breakdown Example
```
Current TCB: DB16000000000004
  Microcode:   219
  SNP:         22
  TEE:         0
  Boot Loader: 4
```

### Different TCB versions from Logs
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

# Full Output Sample
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