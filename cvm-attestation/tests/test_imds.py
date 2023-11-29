import pytest
import requests
from src.imds import get_platform_evidence


def read_hcl_report():
    file = open("tests/report.bin","rb")
    hcl_report = file.read()
    file.close()
    return hcl_report


@pytest.fixture
def mock_http_request(mocker):
    response = requests.Response()
    response.status_code = 200
    response._content= b'{\"quote\": \"unique evidence\"}'
    return mocker.patch('requests.post', return_value=response)


def test_successful_request(mocker, mock_http_request):
    encoded_report = '{\"report\":\"some encoded report\"}'
    evidence = get_platform_evidence(encoded_report)
    assert 'evidence' in evidence
