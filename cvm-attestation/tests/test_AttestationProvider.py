# test_AttestationProvider.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
from src.AttestationProvider import MAAProvider, AttestationProviderException
from src.Isolation import IsolationType
from src.Logger import Logger
from pytest_mock import mocker
from unittest.mock import MagicMock, patch, call
from requests.exceptions import HTTPError


default_logger = Logger("logger")


# Fixture to create a MAAProvider instance
@pytest.fixture
def maa_provider(mocker):
  logger = MagicMock()
  mocker.patch.object(logger, 'info')
  mocker.patch.object(logger, 'error')

  endpoint = "http://someendpoint.com/api"
  return MAAProvider(logger, IsolationType.UNDEFINED, endpoint)


def test_invalid_endpoint_provided():
  isolation = IsolationType.TDX
  invalid_endpoint = "invalid_endpoint"  # This should not be a valid URL

  with pytest.raises(ValueError) as excinfo:
      MAAProvider(default_logger, isolation, invalid_endpoint)
  assert "Invalid endpoint" in str(excinfo.value)


def test_maa_provider_invalid_isolation_type():
  
  invalid_isolation = "invalid_type"
  endpoint = "http://someendpoint.com/api"

  with pytest.raises(ValueError) as excinfo:
      MAAProvider(default_logger, invalid_isolation, endpoint)
  
  assert "Unsupported isolation type" in str(excinfo.value)


def test_create_payload_tdx(maa_provider):
  evidence = 'dummy_evidence'
  runtimes_data = 'dummy_runtimes_data'

  # Set isollation type
  maa_provider.isolation = IsolationType.TDX

  # create payload
  payload = maa_provider.create_payload(evidence, runtimes_data)

  # Assertions to verify the payload structure based on the isolation type
  expected_payload = {
    'quote': evidence,
    'runtimeData': {
        'data': runtimes_data,
        'dataType': 'JSON'
    }
  }
  assert payload == expected_payload


def test_create_payload_sev_snp(maa_provider):
  evidence = 'dummy_evidence'
  runtimes_data = 'dummy_runtimes_data'

  # Set isollation type
  maa_provider.isolation = IsolationType.SEV_SNP

  # create payload
  payload = maa_provider.create_payload(evidence, runtimes_data)

  # Assertions to verify the payload structure based on the isolation type
  expected_payload = {
    'report': evidence,
    'runtimeData': {
        'data': runtimes_data,
        'dataType': 'JSON'
    }
  }
  assert payload == expected_payload


def test_create_payload_fails_with_invalid_parameters(maa_provider):
  invalid_evidence = None
  runtimes_data = 'dummy_runtimes_data'

  # Set isollation type
  maa_provider.isolation = IsolationType.SEV_SNP

  # calls create_payload with invalid parameter
  with pytest.raises(ValueError) as excinfo:
    maa_provider.create_payload(invalid_evidence, runtimes_data)
  assert str(excinfo.value) == "The 'evidence' argument must be an encoded string."

  evidence = 'dummy_evidence'
  invalid_runtimes_data = 123

  # calls create_payload with invalid parameter
  with pytest.raises(ValueError) as excinfo:
    maa_provider.create_payload(evidence, invalid_runtimes_data)
  assert str(excinfo.value) == "The 'runtimes_data' argument must be an encoded string."


def test_attest_guest_success(maa_provider, mocker):
    # Create a mock response object with passing attributes
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"token": "encoded_token_value"}'
    mocker.patch('requests.post', return_value=mock_response)

    # Call attest guest 
    evidence = {'dummy_key': 'dummy_value'}
    result = maa_provider.attest_guest(evidence)
    assert result == 'encoded_token_value'


def test_attest_guest_fails_with_http_401_after_retries(maa_provider, mocker):
  # Create a mock response object with failing attributes
  mock_response = MagicMock()
  mock_response.status_code = 401
  mock_response.text = 'Error message'

  with patch('time.sleep', return_value=None) as mock_sleep:
    with pytest.raises(AttestationProviderException) as excinfo:
      with patch('requests.post', return_value=mock_response) as mock_post:
        maa_provider.attest_guest({'dummy_key': 'dummy_value'})
      assert mock_post.call_count == 5
    assert 'Unexpected status code: 401, error: Error message' in str(excinfo.value)
    
    # request should be sent using exponential backoff
    mock_sleep.assert_has_calls(calls=[
      call(1),
      call(2),
      call(4),
      call(8)])
    assert mock_sleep.call_count == 4


def test_attest_guest_fails_with_exception_after_retries(maa_provider, mocker):
  mocker.patch('requests.post', side_effect=HTTPError("HTTP Error occurred"))

  with patch('time.sleep', return_value=None) as mock_sleep:
    with pytest.raises(AttestationProviderException) as excinfo:
      with patch('requests.post', side_effect=HTTPError("HTTP Error occurred")) as mock_post:
        maa_provider.attest_guest({'dummy_key': 'dummy_value'})
      assert mock_post.call_count == 5
    assert 'Request failed after all retries have been exhausted. Error:' in str(excinfo.value)

  # request should be sent using exponential backoff
    mock_sleep.assert_has_calls(calls=[
      call(1),
      call(2),
      call(4),
      call(8)])
    assert mock_sleep.call_count == 4



def test_attest_platform_success(maa_provider, mocker):
    # Create a mock response object with passing attributes
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '{"token": "encoded_token_value"}'
    mocker.patch('requests.post', return_value=mock_response)

    # Call attest platform 
    evidence = 'some_base64url_encoded_evidence'
    runtimes_data = 'some_base64url_encoded_data'
    maa_provider.isolation = IsolationType.TDX
    result = maa_provider.attest_platform(evidence, runtimes_data)

    assert result == 'encoded_token_value'


def test_attest_platform_fails_with_http_401_after_retries(maa_provider, mocker):
  # Create a mock response object with failing attributes
  mock_response = MagicMock()
  mock_response.status_code = 401
  mock_response.text = 'platform_http_error'

  with patch('time.sleep', return_value=None) as mock_sleep:
    with pytest.raises(AttestationProviderException) as excinfo:
      with patch('requests.post', return_value=mock_response) as mock_post:
        maa_provider.attest_guest({'dummy_key': 'dummy_value'})
      assert mock_post.call_count == 5
    assert f'Unexpected status code: 401, error: {mock_response.text}' in str(excinfo.value)
  
  # request should be sent using exponential backoff
  mock_sleep.assert_has_calls(calls=[
    call(1),
    call(2),
    call(4),
    call(8)])
  assert mock_sleep.call_count == 4


def test_attest_platform_fails_with_exception_after_retries(maa_provider, mocker):
  with patch('time.sleep', return_value=None) as mock_sleep:
    with pytest.raises(AttestationProviderException) as excinfo:
      with patch('requests.post', side_effect=HTTPError("platform_htt_except")) as mock_post:
        maa_provider.attest_guest({'dummy_key': 'dummy_value'})
      assert mock_post.call_count == 5
    assert f'Request failed after all retries have been exhausted. Error: platform_htt_except' in str(excinfo.value)
  
  # request should be sent using exponential backoff
  mock_sleep.assert_has_calls(calls=[
    call(1),
    call(2),
    call(4),
    call(8)])
  assert mock_sleep.call_count == 4


def test_attest_platform_returns_None_after_http_response_400(maa_provider, mocker):
  # Create a mock response object with passing attributes
  mock_response = MagicMock()
  mock_response.status_code = 400
  mock_response.text = 'some_failure_from_provider'
  mocker.patch('requests.post', return_value=mock_response)

  # Call attest platform 
  evidence = 'some_base64url_encoded_evidence'
  runtimes_data = 'some_base64url_encoded_data'
  maa_provider.isolation = IsolationType.SEV_SNP
  result = maa_provider.attest_platform(evidence, runtimes_data)

  assert result == None


def test_attest_guest_returns_None_after_http_response_400(maa_provider, mocker):
  # Create a mock response object with passing attributes
  mock_response = MagicMock()
  mock_response.status_code = 400
  mock_response.text = 'some_failure_from_provider'
  mocker.patch('requests.post', return_value=mock_response)

  # Call attest guest 
  evidence = {'dummy_key': 'dummy_value'}
  maa_provider.isolation = IsolationType.SEV_SNP
  result = maa_provider.attest_guest(evidence)

  assert result == None


def test_attest_platform_retries_with_retry_after_header_until_max_retries(maa_provider, mocker):
  mock_response = MagicMock()
  mock_response.status_code = 429
  mock_response.headers = {'Retry-After': '2'}
  mock_response.text = "Too many requests"

  mocker.patch('requests.post', return_value=mock_response)

  with patch('time.sleep', return_value=None) as mock_sleep:
    evidence = 'some_base64url_encoded_evidence'
    runtimes_data = 'some_base64url_encoded_data'
    maa_provider.isolation = IsolationType.TDX

    with pytest.raises(AttestationProviderException) as excinfo:
      maa_provider.attest_platform(evidence, runtimes_data)

      # Ensure function attempted the request 5 times before failing
      assert mock_response.call_count == 5

      # Ensure sleep was called correctly (5 retries = 4 sleeps)
      mock_sleep.assert_has_calls([call(2), call(2), call(2), call(2)])
      assert mock_sleep.call_count == 4


def test_attest_platform_succeeds_after_retries(maa_provider, mocker):
  mock_responses = [
    MagicMock(status_code=429, headers={'Retry-After': '10'}, text="Too many requests"),
    MagicMock(status_code=429, headers={'Retry-After': '5'}, text="Too many requests"),
    MagicMock(status_code=200, text='{"token": "encoded_token_value"}')
  ]

  mock_post = mocker.patch('requests.post', side_effect=mock_responses)

  with patch('time.sleep', return_value=None) as mock_sleep:
    evidence = 'some_base64url_encoded_evidence'
    runtimes_data = 'some_base64url_encoded_data'
    maa_provider.isolation = IsolationType.TDX
    result = maa_provider.attest_platform(evidence, runtimes_data)

    assert result == "encoded_token_value"
    assert mock_post.call_count == 3  # Two failures, then success
    mock_sleep.assert_has_calls([call(10), call(5)])  # Retries before success

def test_attest_guest_succeeds_after_retries(maa_provider, mocker):
  mock_responses = [
    MagicMock(status_code=429, headers={'Retry-After': '10'}, text="Too many requests"),
    MagicMock(status_code=429, headers={'Retry-After': '5'}, text="Too many requests"),
    MagicMock(status_code=200, text='{"token": "encoded_token_value"}')
  ]

  mock_post = mocker.patch('requests.post', side_effect=mock_responses)

  with patch('time.sleep', return_value=None) as mock_sleep:
    evidence = {'dummy_key': 'dummy_value'}
    maa_provider.isolation = IsolationType.TDX
    result = maa_provider.attest_guest(evidence)

    assert result == "encoded_token_value"
    assert mock_post.call_count == 3  # Two failures, then success
    mock_sleep.assert_has_calls([call(10), call(5)])  # Retries before success


def test_should_try_backoff_when_retry_after_not_present(maa_provider, mocker):
  # Create a mock response object with not Retry-After in the header
  mock_responses = [
    MagicMock(status_code=429, headers={}, text="Too many requests"),
    MagicMock(status_code=429, headers={}, text="Too many requests"),
    MagicMock(status_code=200, text='{"token": "encoded_token_value"}')
  ]

  mock_post = mocker.patch('requests.post', side_effect=mock_responses)

  # Since the Retry-After header is not present, we should use the default backoff time
  # which is 1 second for the first retry, and then exponential backoff for subsequent retries.
  with patch('time.sleep', return_value=None) as mock_sleep:
    evidence = {'dummy_key': 'dummy_value'}
    maa_provider.isolation = IsolationType.TDX
    result = maa_provider.attest_guest(evidence)

    assert result == "encoded_token_value"
    assert mock_post.call_count == 3  # Two failures, then success
    mock_sleep.assert_has_calls([call(1), call(2)])  # Retries before success