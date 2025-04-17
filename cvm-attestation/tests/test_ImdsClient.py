# test_ImdsClient.py
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import json
from unittest.mock import MagicMock, patch
import requests
from src.ImdsClient import ImdsClient, TDQuoteException, VcekCertException


# Some mock data
snp_data = {
    'vcekCert': 'some_cert',
    'certificateChain': 'some_chain',
    'tcbm': 'some_tcb_number'
}
tdx_data = {'quote': 'some_evidence'}


# Fixture to create an ImdsClient instance
@pytest.fixture
def imds_client(mocker):
    logger = MagicMock()
    mocker.patch.object(logger, 'info')
    mocker.patch.object(logger, 'error')

    return ImdsClient(logger)


def test_successful_td_quote_request(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = tdx_data
    mocker.patch('requests.request', return_value=mock_response)

    evidence = imds_client.get_td_quote('encoded_report')
    assert evidence == 'some_evidence'


def test_successful_vcek_cert_request(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = snp_data
    mocker.patch('requests.request', return_value=mock_response)

    evidence = imds_client.get_vcek_certificate()
    assert bytes('some_cert', 'utf-8') in evidence

def test_td_quote_request_retries_if_error_code_is_returned(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = 'Error message'

    with patch('time.sleep', return_value=None) as mock_sleep:
        with pytest.raises(TDQuoteException) as excinfo:
            with patch('requests.request', return_value=mock_response) as mock_post:
                imds_client.get_td_quote('some_encoded_report')
            assert mock_post.call_count == 5
        assert 'Error 400: Error message' in str(excinfo.value)
        assert mock_sleep.call_count == 4


def test_td_quote_request_retries_if_http_exception_is_encountered(mocker, imds_client):
    effect = requests.exceptions.RequestException("some_error")

    with patch('time.sleep', return_value=None) as mock_sleep:
        with patch('requests.request', side_effect=effect) as mock_post:
            with pytest.raises(TDQuoteException) as excinfo:
                imds_client.get_td_quote('some_encoded_report')
            assert 'HTTP request failed with error some_error' in str(excinfo.value)
        assert mock_post.call_count == 5
        assert mock_sleep.call_count == 4


def test_vcek_cert_request_retries_if_error_code_is_returned(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = 'Error message'

    with patch('time.sleep', return_value=None) as mock_sleep:
        with pytest.raises(VcekCertException) as excinfo:
            with patch('requests.request', return_value=mock_response) as mock_post:
                imds_client.get_vcek_certificate()
            assert mock_post.call_count == 5
        assert 'Error 400: Error message' in str(excinfo.value)
        assert mock_sleep.call_count == 4


def test_vcek_cert_request_retries_if_http_exception_is_encountered(mocker, imds_client):
    effect = requests.exceptions.RequestException("some_error")

    with patch('time.sleep', return_value=None) as mock_sleep:
        with patch('requests.request', side_effect=effect) as mock_post:
            with pytest.raises(VcekCertException) as excinfo:
                imds_client.get_vcek_certificate()
            assert 'HTTP request failed with error some_error' in str(excinfo.value)
        assert mock_post.call_count == 5
        assert mock_sleep.call_count == 4


def test_td_quote_fails_to_decode_json_response(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)

    with patch('requests.request', return_value=mock_response) as mock_post:
        with pytest.raises(TDQuoteException) as excinfo:
            imds_client.get_td_quote('some_encoded_report')
        assert 'JSON decoding error' in str(excinfo.value)
    assert mock_post.call_count == 1


def test_vcek_cert_fails_to_decode_json_response(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)

    with patch('requests.request', return_value=mock_response) as mock_post:
        with pytest.raises(VcekCertException) as excinfo:
            imds_client.get_vcek_certificate()
        assert 'JSON decoding error' in str(excinfo.value)
    assert mock_post.call_count == 1