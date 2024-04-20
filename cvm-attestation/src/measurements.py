# measurements.py
#
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

import sys

# Check the platform
if sys.platform.startswith('win32'):
    # Import modules specific to Windows
    import winreg
# Add more conditions for other platforms if needed

# Now you can use the imported module as needed

# Define the registry path
path = r'SYSTEM\\CurrentControlSet\\Control\\IntegrityServices'
value_name = 'WBCL'

LINUX_TCG_LOG_PATH = "/sys/kernel/security/tpm0/binary_bios_measurements"

def get_measurements(os):
    if os == "Linux":
        binary_data = b''
        # Open the file in binary read mode
        with open(LINUX_TCG_LOG_PATH, 'rb') as file:
            binary_data = file.read()
        return binary_data

    # Access the key
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)

    tcg_logs = bytearray()
    # Read the values
    try:
        count = 0
        while True:
            name, value, type = winreg.EnumValue(key, count)
            if name == value_name:
                print(name, value)
                tcg_logs = value
            count += 1
    except WindowsError:
        pass

    # Don't forget to close the key when done
    winreg.CloseKey(key)
    return tcg_logs