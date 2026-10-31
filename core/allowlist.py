
from pathlib import Path

WEBVIEW2_EXECUTABLE = "msedgewebview2.exe"


def is_webview2(process_name: str, executable_path: str = "") -> bool:
    if process_name.lower() != WEBVIEW2_EXECUTABLE:
        return False

    if not executable_path:
        return False

    path = Path(executable_path)

    return (
        path.name.lower() == WEBVIEW2_EXECUTABLE
        and "microsoft" in str(path).lower()
        and "webview2" in str(path).lower()
    )


def is_allowed_process(process_name: str, executable_path: str = "") -> bool:
    return is_webview2(process_name, executable_path)
