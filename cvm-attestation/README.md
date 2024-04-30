# Python Attestation Sample App
Remote Attestation empowers a `relying party`, whether it be the workload owner or the user, to authenticate that their workload is operating on a platform equipped with `Intel TDX` technology before divulging sensitive information. In this instance, we undertake the assessment of the `Hardware Report's` integrity and trustworthiness through the services of an Attestation Provider. This application serves as an instructive demonstration highlighting the implementation of Remote Attestation using Python programming language.

## Overview

![Attestation](img/attest.png)

## Intall Dependencies and Build CLI Tool
Install all the dependencies and build the CLI tool called `attest`
```
sudo ./install
```

## Uninstall the `attest` CLI Tool
```
pip3 uninstall attest -y
```

## Run CLI Tool
To run the cli tool use the following command:
```
attest  --c config_sample.json
```

### `--c` Config File Option
Option to set config file
```
attest  --c config_sample.json
```

### `--t` Attestation Type Option
Option to provide type of attestation to be run

#### Platform
Attest the Hardware using the Machines Hardware Report
```
attest  --c config_sample.json --t Platform
```

#### Guest
Attest the Hardware and the Guest measurements
```
attest  --c config_sample.json --t Guest
```


The console output will contain the `Token` returned by the Attestation Provider as well as some of the claims parsed from the token.

## TDX 
### Attesting with MAA
```
Attested Platform Successfully!!

Claims:
        TCB Status:  UpToDate
        TCB SVN:  02010600000000000000000000000000
        Attestation Type:  tdxvm

CVM Configuration:
        Console Enabled:  True
        Secure Boot Enabled:  True
        TPM Enabled:  True
        User Data:  67BE2D9DE456C30EBB165EE6F0A04684555C23068F63E973C7B1DCB4A25817D20000000000000000000000000000000000000000000000000000000000000000
        TPM Persisted:  False
```

### Attesting with Intel Trust Authority
```
Attested Platform Successfully!!

Claims:
        TCB Status:  OK
        TEE Debuggable:  False
        Evidence Type:  TDX
```

## SEV-SNP
### Attesting with MAA
```
Attested Platform Successfully!!

Claims:
        Attestation Type:  sevsnpvm
        Status:  azure-compliant-cvm
        Bootloader SVN:  3
        Guest SVN:  5
        Microcode SVN:  115

CVM Configuration:
        Console Enabled:  True
        Secure Boot Enabled:  True
        TPM Enabled:  True
        User Data:  00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```