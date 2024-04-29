# test_Measurements.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import pytest
import sys
from src.measurements import get_measurements
# Check the platform
if sys.platform.startswith('win32'):
    # Import modules specific to Windows
    import winreg

# Define the registry path
PATH = r'SYSTEM\\CurrentControlSet\\Control\\IntegrityServices'
VALUE_NAME = 'WBCL'


@pytest.fixture
def mock_winreg(mocker):
    mocker.patch.object(winreg, 'OpenKey')


@pytest.mark.skipif(sys.platform != "windows", reason="only runs on windows")
def test_get_measurements():
    winreg.OpenKey.assert_called_with(winreg.HKEY_LOCAL_MACHINE, PATH, 0, winreg.KEY_READ)
    # Expected value from the registry
    expected_value = b'some bytes'  # Replace with the actual expected value

    # Call the function
    result = get_measurements()

    # Assert that the result matches the expected value
    assert result == expected_value