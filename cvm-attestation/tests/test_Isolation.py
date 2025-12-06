# test_isolation.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from src.isolation import IsolationType, Isolation, SnpEvidence, TdxEvidence, TrustedLaunchEvidence

# Test case for the SnpEvidence class
def test_snp_evidence():
    evidence = SnpEvidence(snp_report=b'report', runtime_data=b'data', vcek_cert=b'cert')
    evidence.validate()
    evidence_data = evidence.get_evidence()

    assert evidence_data["Type"] == "SevSnp"
    assert "Proof" in evidence_data["Evidence"]
    assert "RunTimeData" in evidence_data["Evidence"]

# Test case for the TdxEvidence class
def test_tdx_evidence():
    evidence = TdxEvidence(encoded_hw_evidence=b'proof_data', runtime_data=b'tdx_data')
    evidence.validate()
    evidence_data = evidence.get_evidence()

    assert evidence_data["Type"] == "Tdx"
    assert "Proof" in evidence_data["Evidence"]
    assert "RunTimeData" in evidence_data["Evidence"]

# Test case for the TrustedLaunchEvidence class
def test_trusted_launch_evidence():
    evidence = TrustedLaunchEvidence()
    evidence.validate()
    evidence_data = evidence.get_evidence()

    assert evidence_data["Type"] == "TrustedLaunch"
    assert "Evidence" not in evidence_data

# Test case for the Isolation class
def test_isolation():
    snp_evidence = SnpEvidence(snp_report=b'report', runtime_data=b'data', vcek_cert=b'cert')
    tdx_evidence = TdxEvidence(encoded_hw_evidence=b'proof_data', runtime_data=b'tdx_data')
    trusted_launch_evidence = TrustedLaunchEvidence()

    isolation_snp = Isolation(IsolationType.SEV_SNP, snp_evidence)
    assert isolation_snp.get_values()["Type"] == "SevSnp"

    isolation_tdx = Isolation(IsolationType.TDX, tdx_evidence)
    assert isolation_tdx.get_values()["Type"] == "Tdx"

    isolation_trusted_launch = Isolation(IsolationType.TRUSTED_LAUNCH, trusted_launch_evidence)
    assert isolation_trusted_launch.get_values()["Type"] == "TrustedLaunch"

# Test case for validation method
def test_validation():
    snp_evidence = SnpEvidence(snp_report=b'report', runtime_data=b'data', vcek_cert=b'cert')
    isolation = Isolation(IsolationType.SEV_SNP, snp_evidence)
    assert isolation.validate() is None

    tdx_evidence = TdxEvidence(encoded_hw_evidence=b'proof_data', runtime_data=b'tdx_data')
    isolation = Isolation(IsolationType.TDX, tdx_evidence)
    assert isolation.validate() is None