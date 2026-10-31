
import winreg

POLICY_PATH = r"SOFTWARE\Policies\Microsoft\Edge"


def inspect_policies():
    results = {}

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            POLICY_PATH,
            0,
            winreg.KEY_READ
        )

        index = 0

        while True:
            try:
                name, value, value_type = winreg.EnumValue(key, index)
                results[name] = {
                    "value": value,
                    "type": value_type
                }
                index += 1

            except OSError:
                break

        winreg.CloseKey(key)

    except FileNotFoundError:
        return {"exists": False, "policies": {}}

    return {"exists": True, "policies": results}
