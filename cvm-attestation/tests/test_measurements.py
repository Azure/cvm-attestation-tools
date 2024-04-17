import pytest
import winreg
from src.measurements import get_measurements


# Define the registry path
PATH = r'SYSTEM\\CurrentControlSet\\Control\\IntegrityServices'
VALUE_NAME = 'WBCL'


@pytest.fixture
def mock_winreg(mocker):
    mocker.patch.object(winreg, 'OpenKey')


# Test case for the get_measurements function
def test_get_measurements():
    winreg.OpenKey.assert_called_with(winreg.HKEY_LOCAL_MACHINE, PATH, 0, winreg.KEY_READ)
    # Expected value from the registry
    expected_value = b'some bytes'  # Replace with the actual expected value

    # Call the function
    result = get_measurements()

    # Assert that the result matches the expected value
    assert result == expected_value