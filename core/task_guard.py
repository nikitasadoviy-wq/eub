import subprocess
import json


def inspect_tasks():
    results = []

    try:
        output = subprocess.run(
            [
                "schtasks.exe",
                "/query",
                "/fo",
                "CSV",
                "/v"
            ],
            capture_output=True,
            text=True,
            timeout=20
        )

        if output.returncode != 0:
            return results

        import csv
        from io import StringIO

        reader = csv.DictReader(StringIO(output.stdout))

        for task in reader:
            name = task.get("TaskName", "")

            if "edge" not in name.lower():
                continue

            results.append({
                "name": name,
                "status": task.get("Status", "Unknown"),
                "next_run": task.get("Next Run Time", "Unknown")
            })

    except (subprocess.TimeoutExpired, OSError):
        pass

    return results
def inspect_scheduled_tasks():
    return inspect_tasks()