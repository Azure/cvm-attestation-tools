# test_isolation.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from src.isolation import IsolationType, Isolation, SnpEvidence, TdxEvidence

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

# Test case for the Isolation class
def test_isolation():
    snp_evidence = SnpEvidence(snp_report=b'report', runtime_data=b'data', vcek_cert=b'cert')
    tdx_evidence = TdxEvidence(encoded_hw_evidence=b'proof_data', runtime_data=b'tdx_data')

    isolation_snp = Isolation(IsolationType.SEV_SNP, snp_evidence)
    assert isolation_snp.get_values()["Type"] == "SevSnp"

    isolation_tdx = Isolation(IsolationType.TDX, tdx_evidence)
    assert isolation_tdx.get_values()["Type"] == "Tdx"

# Test case for validation method
def test_validation():
    snp_evidence = SnpEvidence(snp_report=b'report', runtime_data=b'data', vcek_cert=b'cert')
    isolation = Isolation(IsolationType.SEV_SNP, snp_evidence)
    assert isolation.validate() is None

    tdx_evidence = TdxEvidence(encoded_hw_evidence=b'proof_data', runtime_data=b'tdx_data')
    isolation = Isolation(IsolationType.TDX, tdx_evidence)
    assert isolation.validate() is None