# How to verify the TCB Version from an AMD SEV-SNP Confidential VM
This guide provides detailed instructions on how to interpret the Trusted Computing Base (TCB) version from an AMD SEV-SNP attestation report and make sure they are the expected values. The TCB version is a critical component in ensuring the security and integrity of a Confidential VM. By following this guide, users will be able to verify the TCB version against AMD's specifications, ensuring that their environment meets the necessary security standards. For more information on AMD SEV-SNP and TCB, refer to the official [AMD SEV-SNP Attestation](https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf) documentation.

> **NOTE:** Thourghout this document we will be using an `Azure v5 Confidential VM`.

## 1. Pre-requisites
In order to read the `SEV-SNP` attestation report, we need to install some tools that will allow us to fetch and display all the information from this report. Please follow the guide on [How to read SEV-SNP attestation report](./How_to_read_attestation_report.md) to install the tools.

## 2. Verify that `read_report` tool is installed
To check that the attestaton tool we need is installed, run the following command `read_report` on Windows and `sudo read_report` on Linux to verify that the command is installed and ready.

### Sample Output
If the command is ready, the output should look similar to the following:

```
TSS.Py::__INIT__.PY invoked
2025-02-04 15:23:52,824 - read_report - INFO - Attestation started...
2025-02-04 15:23:52,825 - read_report - INFO - Report type selected: snp_report
2025-02-04 15:23:52,825 - handle_hardware_report - INFO - Reading hardware report: snp_report
...
2025-02-04 17:01:00,698 - handle_hardware_report - INFO - Got attestation report successfully!
```

## 3. Reading the Attestation Report
To get the SEV-SNP attestation report run the `read_report` command:

### Windows
```
read_report
```

### Linux
```
sudo read_report
```

### SEV-SNP Attestation Report Output

> **IMPORTANT:** The following report is captured on an `Azure Standard DC2as v5` SKU which is an AMD SEV-SNP Confidential VM. For more on how to create a Confidential VM follow [Quick Create Confidential VM on Azure Portal](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-confidential-vm-portal)

```
Attestation Report (1184 bytes):
Version:                      2
Guest SVN:                    8

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
  Microcode:   219 (DB)
  SNP:         22 (16)
  Reserved:    0 (0)
  TEE:         0 (0)
  Boot Loader: 4 (4)

Platform Info (1):
  SMT Enabled:               1
  TSME Enabled:              0
  ECC Enabled:               0
  RAPL Disabled:             0
  Ciphertext Hiding Enabled: 0

Author Key Encryption:      False
Report Data:                     
eb 19 c8 38 be c7 ab d2 ed 72 de 17 98 8c 41 8d
97 68 14 b0 85 8c 74 06 18 73 de 0e 0a 98 2a b3
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Measurement:                     
ff d9 2c 5d 52 07 af ad f3 b9 3b e3 00 06 0a 98
f9 b9 6b d2 a1 30 0c 97 f1 04 2f 2b 5f 31 3b 96
4f fc 3c 14 64 5a 7b 70 6c 5f 6f e5 cc fa 51 d7

Host Data:                     
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

ID Key Digest:                     
03 56 21 58 82 a8 25 27 9a 85 b3 00 b0 b7 42 93
1d 11 3b f7 e3 2d de 2e 50 ff de 7e c7 43 ca 49
1e cd d7 f3 36 dc 28 a6 e0 b2 bb 57 af 7a 44 a3

Report ID:                     
64 32 3f 67 41 af 34 bc 43 98 ee 1c b0 84 ad e5
bb ac 65 1c 0c 8c 54 62 82 62 24 a8 e1 63 2e ed

Report ID Migration Agent:                     
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff

Reported TCB:
TCB Version: D315000000000004
  Microcode:   211 (D3)
  SNP:         21 (15)
  Reserved:    0 (0)
  TEE:         0 (0)
  Boot Loader: 4 (4)

Chip ID:                     
30 60 39 13 1a 84 af 44 95 11 3e 96 94 19 d6 8f
2a 3a 3a 65 06 cf 33 89 b1 b8 df 93 7a ef a2 c6
c1 46 f4 9a aa ff 25 1a 2f 61 f5 c9 93 70 c0 ee
33 6a a0 3f df 64 f9 04 3f ef b6 3c 49 2b 34 88

Committed TCB: D515000000000004
  Microcode:   213 (D5)
  SNP:         21 (15)
  Reserved:    0 (0)
  TEE:         0 (0)
  Boot Loader: 4 (4)

Current Build:                20
Current Minor:                55
Current Major:                1
Committed Build:              17
Committed Minor:              55
Committed Major:              1

Launched TCB: D515000000000004
  Microcode:   213 (D5)
  SNP:         21 (15)
  Reserved:    0 (0)
  TEE:         0 (0)
  Boot Loader: 4 (4)

Signature:                     
  R Component:
70 7a 1d 59 7c 87 64 f7 91 24 e8 5c 76 6d c0 a4
91 6d 60 89 a5 a8 4f 02 79 18 57 38 f6 db 8c 58
06 e2 d1 6d 8b 79 99 7f 36 6b 3d 46 d2 75 1c 5f
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00

  S Component:
c0 a1 be 4e 98 00 02 94 d3 a2 d8 90 aa 22 2c 0f
6c 16 89 b2 8e 1a b2 7c 04 5f 45 5b 21 35 ca f1
cf e0 a3 c6 e1 d0 ca 33 01 f8 f3 06 2a d5 5b f4
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
```

## 4. Checking the TCB Versions
After obtaining the SEV-SNP attestation report, we can see that there are multiple TCB versions which are listed below. With the `Current TCB` we can check the currently running `platform firmware` and `microcode`.

#### List of TCB Versions:
- **CURRENT_TCB:** Security Version Numbers (SVNs) of the currently executing platform firmware and  microcode
- **COMMITTED_TCB:** SVNs of the anti-rollback minimum of the platform firmware and microcode
- **REPORTED_TCB:** Hypervisor has option to report a lower version to ease continuity on TCB update
- **LAUNCHED_TCB:** SVNs of the version of the platform firmware and microcode at time of launch of this guest

### Different TCB Versions from the Report
From the attestation report we can see the different TCB versions that are reported by the machine.

```
2025-02-04 17:01:00,696 - log_snp_report - INFO - Attestation report size: 1184 bytes
2025-02-04 17:01:00,696 - log_snp_report - INFO - Report version: 2
2025-02-04 17:01:00,696 - log_snp_report - INFO - Report guest svn: 8
2025-02-04 17:01:00,696 - log_snp_report - INFO - Current TCB version: DB16000000000004
2025-02-04 17:01:00,696 - log_snp_report - INFO - Reported TCB version: D315000000000004
2025-02-04 17:01:00,696 - log_snp_report - INFO - Commited TCB version: D515000000000004
2025-02-04 17:01:00,696 - log_snp_report - INFO - Launched TCB version: D515000000000004
```

> **NOTE:** From the attestation report dump above, we can see that the current TCB (the currently executing firmware and microcode) is `DB16000000000004`.


### Current TCB Version from the Report
From the attestation report we can get the `current TCB` version which is displayed as the hex value `0xDB16000000000004` in `little` endian. Each of the fields inside this value are shown below by its name, integer value, and hex representation.
```
Current TCB: DB16000000000004
  Microcode:   219 (DB)
  SNP:         22 (16)
  Reserved:    0 (0)
  TEE:         0 (0)
  Boot Loader: 4 (4)
```


#### Current TCB Version Breakdown
From the TCB version above, we can break it down into its components.
```
DB16000000000004
```
| Byte Order | Value | Description |
|------------|-------|-------------|
| [56:63]    | 0xDB  | Microcode Patch Level |
| [48:55]    | 0x16  | SNP FW SVN |
| [16:47]    | 0x00000000 | Reserved |
| [8:15]     | 0x00  | OS SVN |
| [0:7]      | 0x04  | Bootloader SVN |

