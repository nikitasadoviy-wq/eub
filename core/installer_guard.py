
import psutil

INSTALLER_NAMES = {
    "microsoftedgeinstaller.exe",
    "microsoftedgeupdate.exe",
    "msedgeupdate.exe"
}


def inspect_installers():
    detected = []

    for process in psutil.process_iter(
        ["pid", "name", "exe", "cmdline"]
    ):
        try:
            info = process.info
            name = info["name"]

            if not name or name.lower() not in INSTALLER_NAMES:
                continue

            detected.append({
                "pid": info["pid"],
                "name": name,
                "path": info["exe"],
                "command_line": info["cmdline"] or []
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return detected
