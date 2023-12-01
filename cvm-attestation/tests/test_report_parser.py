import pytest
from src.report_parser import extract_hw_report, extract_runtime_data

def read_hcl_report():
    file = open("tests/report.bin","rb")
    hcl_report = file.read()
    file.close()

    return hcl_report


def test_extract_td_report():
    EXPECTED_TD_REPORT_SIZE = 1024

    hcl_report = read_hcl_report()
    td_report = extract_hw_report(hcl_report)

    assert len(td_report) == EXPECTED_TD_REPORT_SIZE

def test_extract_runtime_data():
    hcl_report = read_hcl_report()
    runtime_data = str(extract_runtime_data(hcl_report), 'utf-8')

    assert 'vm-configuration' in runtime_data
    assert 'tpm-enabled' in runtime_data
    assert 'secure-boot' in runtime_data
    assert 'user-data' in runtime_data