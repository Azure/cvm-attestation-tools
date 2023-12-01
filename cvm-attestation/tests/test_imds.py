import pytest
import requests
from src.imds import get_td_quote, get_vcek_certificate


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


def test_successful_td_quote_request(mocker, mock_http_request):
    encoded_report = '{\"report\":\"some encoded report\"}'
    evidence = get_td_quote(encoded_report)
    assert 'evidence' in evidence
