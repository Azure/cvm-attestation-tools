# test_ReportParser.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import os
import pytest
from src.ReportParser import ReportParser

def read_hcl_report():
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "hardware_reports\\report.bin")
    file = open(file_path,"rb")
    hcl_report = file.read()
    file.close()

    return hcl_report


def test_extract_td_report():
    EXPECTED_TD_REPORT_SIZE = 1024

    hcl_report = read_hcl_report()
    td_report = ReportParser.extract_hw_report(hcl_report)

    assert len(td_report) == EXPECTED_TD_REPORT_SIZE

def test_extract_runtime_data():
    hcl_report = read_hcl_report()
    runtime_data = str(ReportParser.extract_runtimes_data(hcl_report), 'utf-8')

    assert 'vm-configuration' in runtime_data
    assert 'tpm-enabled' in runtime_data
    assert 'secure-boot' in runtime_data
    assert 'user-data' in runtime_data