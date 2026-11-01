
from pathlib import Path


def analyze_trust(process: dict) -> dict:
    """
    Read-only trust assessment.
    This module never terminates or modifies processes.
    """

    reasons = []

    executable = process.get("executable")
    pe_info = process.get("pe") or {}
    signature_info = process.get("signature") or {}

    if not executable:
        return {
            "trust": "UNKNOWN",
            "reasons": ["MISSING_EXECUTABLE_PATH"],
        }

    if not Path(executable).is_file():
        return {
            "trust": "UNKNOWN",
            "reasons": ["FILE_NOT_FOUND"],
        }

    if pe_info.get("error"):
        return {
            "trust": "INVALID",
            "reasons": ["PE_ANALYSIS_ERROR"],
        }

    if not pe_info.get("is_pe", False):
        return {
            "trust": "INVALID",
            "reasons": ["NOT_A_VALID_PE_FILE"],
        }

    if signature_info.get("error"):
        return {
            "trust": "UNKNOWN",
            "reasons": ["SIGNATURE_ANALYSIS_ERROR"],
        }

    status = str(signature_info.get("Status") or "").lower()
    signer = str(signature_info.get("Signer") or "")

    if status != "valid":
        return {
            "trust": "SUSPICIOUS",
            "reasons": ["SIGNATURE_NOT_VALID"],
        }

    if "Microsoft Corporation" not in signer:
        return {
            "trust": "UNKNOWN",
            "reasons": ["UNEXPECTED_SIGNER"],
        }

    return {
        "trust": "TRUSTED",
        "reasons": ["VALID_PE", "VALID_MICROSOFT_SIGNATURE"],
    }
