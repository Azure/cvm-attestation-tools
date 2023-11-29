import pytest
import requests
import logging
from src.verifier import verify_evidence


@pytest.fixture
def mock_http_request(mocker):
    response = requests.Response()
    response.status_code = 200
    response._content= b'{\"token\": \"encoded token\"}'
    return mocker.patch('requests.post', return_value=response)


@pytest.fixture
def mock_http_fail_request(mocker):

    response = requests.Response()
    response.status_code = 400
    response._content= b'Bad Request'
    return mocker.patch('requests.post', return_value=response)

@pytest.fixture
def mock_logging_error(mocker):
    mocker.patch.object(logging, 'error')


def test_successful_request(mocker, mock_http_request):
    quote = 'encoded quote'
    runtime_data = 'encoded runtime data'
    encoded_token = verify_evidence(quote, runtime_data)
    assert 'encoded token' in encoded_token


def test_failed_request(mocker, mock_http_fail_request, mock_logging_error):
    quote = 'encoded quote'
    runtime_data = 'encoded runtime data'
    encoded_token = verify_evidence(quote, runtime_data)

    endpoint=''

    logging.error.assert_called_with("Failed to verify evidence, error: ", 'Bad Request')
    assert logging.error.call_count == 1