import winreg

# Define the registry path
path = r'SYSTEM\\CurrentControlSet\\Control\\IntegrityServices'
value_name = 'WBCL'


def get_measurements():
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