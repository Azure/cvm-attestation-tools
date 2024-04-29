# test_Isolation.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from src.Isolation import IsolationInfo, IsolationType

# Test case for the IsolationInfo class
def test_isolation_info():
    # Create an instance of IsolationInfo with default values
    default_info = IsolationInfo()
    assert default_info.isolation_type == IsolationType.UNDEFINED
    assert default_info.snp_report == b''
    assert default_info.runtime_data == b''
    assert default_info.vcek_cert == ""

    # Create an instance of IsolationInfo with custom values
    custom_info = IsolationInfo(
        isolation_type=IsolationType.SEV_SNP,
        snp_report=b'some_report',
        runtime_data=b'some_data',
        vcek_cert='some_cert'
    )
    assert custom_info.isolation_type == IsolationType.SEV_SNP
    assert custom_info.snp_report == b'some_report'
    assert custom_info.runtime_data == b'some_data'
    assert custom_info.vcek_cert == 'some_cert'
