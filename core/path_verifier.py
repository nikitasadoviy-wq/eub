
from pathlib import Path


EXPECTED_PATHS = {
    "BROWSER": [
        ("microsoft", "edge", "application"),
    ],
    "UPDATER": [
        ("microsoft", "edgeupdate"),
    ],
    "WEBVIEW2": [
        ("microsoft", "edgewebview", "application"),
    ],
}


def verify_path(process_type: str, executable_path: str) -> dict:
    """
    Checks whether an executable is located in a recognizable
    Microsoft Edge installation directory.

    Read-only. Does not modify files or processes.
    """

    if not executable_path:
        return {
            "status": "UNKNOWN",
            "reason": "MISSING_PATH",
        }

    path = Path(executable_path)

    try:
        if not path.is_file():
            return {
                "status": "UNKNOWN",
                "reason": "FILE_NOT_FOUND",
            }
    except OSError:
        return {
            "status": "UNKNOWN",
            "reason": "PATH_ACCESS_ERROR",
        }

    if path.name.lower() not in {
        "msedge.exe",
        "microsoftedgeupdate.exe",
        "msedgeupdate.exe",
        "msedgewebview2.exe",
        "microsoftedgeinstaller.exe",
        "ie_to_edge_stub.exe",
    }:
        return {
            "status": "UNEXPECTED",
            "reason": "UNRECOGNIZED_EXECUTABLE",
        }

    normalized_parts = tuple(
        part.lower() for part in path.parts
    )

    expected_locations = EXPECTED_PATHS.get(process_type)

    if expected_locations is None:
        return {
            "status": "UNKNOWN",
            "reason": "UNKNOWN_PROCESS_TYPE",
        }

    for expected in expected_locations:
        length = len(expected)

        for index in range(len(normalized_parts) - length + 1):
            if normalized_parts[index:index + length] == expected:
                return {
                    "status": "EXPECTED",
                    "reason": "RECOGNIZED_EDGE_DIRECTORY",
                }

    return {
        "status": "UNEXPECTED",
        "reason": "PATH_NOT_IN_RECOGNIZED_LOCATION",
    }
