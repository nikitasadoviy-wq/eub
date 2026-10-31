
from pathlib import Path


PROCESS_TYPES = {
    "msedge.exe": "BROWSER",
    "microsoftedgeupdate.exe": "UPDATER",
    "msedgeupdate.exe": "UPDATER",
    "microsoftedgeinstaller.exe": "INSTALLER",
    "ie_to_edge_stub.exe": "INSTALLER",
    "msedgewebview2.exe": "WEBVIEW2",
}


def classify_process(name: str, executable_path: str = "") -> str:
    if not name:
        return "UNKNOWN"

    name = name.lower()
    process_type = PROCESS_TYPES.get(name, "UNKNOWN")

    if process_type == "UNKNOWN":
        return "UNKNOWN"

    if executable_path:
        path = Path(executable_path)

        if path.name.lower() != name:
            return "UNKNOWN"

    return process_type
