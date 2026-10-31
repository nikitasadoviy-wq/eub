
import subprocess
import json


def verify_signature(file_path):
    script = (
        "$sig = Get-AuthenticodeSignature -LiteralPath "
        + "'" + file_path.replace("'", "''") + "'; "
        + "[PSCustomObject]@{"
        + "Status=$sig.Status.ToString();"
        + "StatusMessage=$sig.StatusMessage;"
        + "Signer=$sig.SignerCertificate.Subject;"
        + "Issuer=$sig.SignerCertificate.Issuer"
        + "} | ConvertTo-Json -Compress"
    )

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20
    )

    if result.returncode != 0:
        return {"error": result.stderr.strip()}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "Invalid signature response"}