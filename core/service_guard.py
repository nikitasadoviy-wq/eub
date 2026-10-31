
import subprocess


EDGE_SERVICES = [
    "edgeupdate",
    "edgeupdatem"
]


def inspect_services():
    results = []

    for service in EDGE_SERVICES:
        try:
            output = subprocess.run(
                ["sc.exe", "query", service],
                capture_output=True,
                text=True,
                timeout=5
            )

            results.append({
                "name": service,
                "exists": output.returncode == 0,
                "status": output.stdout.strip()
            })

        except subprocess.TimeoutExpired:
            results.append({
                "name": service,
                "exists": False,
                "status": "QUERY_TIMEOUT"
            })

    return results
