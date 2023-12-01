import pytest
from click.testing import CliRunner
from attest import main


def read_hcl_report():
    file = open("tests/report.bin","rb")
    hcl_report = file.read()
    file.close()
    return hcl_report


@pytest.fixture
def mock_get_hcl_report(mocker):
    mock_report = read_hcl_report()
    return mocker.patch('tpm_wrapper.get_hcl_report', return_value=mock_report)

@pytest.fixture
def mock_get_td_quote(mocker):
    evidence = '{\"quote\":\"some quote\"'
    return mocker.patch('src.imds.get_td_quote', return_value=evidence)

@pytest.fixture
def mock_verify_evidence(mocker):
    token = '{\"token\":\"some token\"}'
    return mocker.patch('src.verifier.verify_evidence', return_value=token)


def test_attest_successfully(
    mocker,
    mock_get_hcl_report,
    mock_get_td_quote):

    runner = CliRunner()
    runner.invoke(main, ['--c', 'somefile.json'])
    assert True