# test_imds.py
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
    'certificateChain': 'some_chain'
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
    mock_response.text = json.dumps(tdx_data)
    mocker.patch('requests.post', return_value=mock_response)
    
    evidence = imds_client.get_td_quote('encoded_report')
    assert 'some_evidence' in evidence


def test_successful_vcek_cert_request(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = json.dumps(snp_data)
    mocker.patch('requests.get', return_value=mock_response)
    
    evidence = imds_client.get_vcek_certificate()
    assert bytes('some_cert', 'utf-8') in evidence


def test_td_quote_request_fails_with_http_400(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = 'Error message'
    mocker.patch('requests.post', return_value=mock_response)

    with pytest.raises(TDQuoteException) as excinfo:
        imds_client.get_td_quote('some_encoded_report')
    assert 'Error 400: Error message' in str(excinfo.value)


def test_vcek_cert_request_fails_with_http_400(mocker, imds_client):
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = 'Error message'
    mocker.patch('requests.get', return_value=mock_response)

    with pytest.raises(VcekCertException) as excinfo:
        imds_client.get_vcek_certificate()
    assert 'Error 400: Error message' in str(excinfo.value)