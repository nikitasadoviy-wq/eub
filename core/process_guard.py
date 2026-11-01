
from pathlib import Path

import psutil

from core.process_classifier import classify_process
from core.path_verifier import verify_path
from core.trust_analyzer import analyze_trust
from core.pe_analyzer import analyze_pe
from core.signature_verifier import verify_signature


TARGET_TYPES = {
    "BROWSER",
    "UPDATER",
    "INSTALLER",
    "WEBVIEW2",
}

ANALYSIS_CACHE = {}

CACHE_STATS = {
    "hits": 0,
    "misses": 0,
    "analyzed_files": 0
}


def get_cache_stats():
    return CACHE_STATS.copy()


def analyze_file_cached(file_path):
    path = Path(file_path)

    try:
        stat = path.stat()
    except OSError as error:
        return {"error": str(error)}, {"error": str(error)}

    cache_key = str(path.resolve()).lower()

    file_state = (
        stat.st_size,
        stat.st_mtime_ns,
    )

    cached = ANALYSIS_CACHE.get(cache_key)

    if cached and cached["file_state"] == file_state:
        CACHE_STATS["hits"] += 1
        return cached["pe"], cached["signature"]

    CACHE_STATS["misses"] += 1
    CACHE_STATS["analyzed_files"] += 1

    try:
        pe_info = analyze_pe(str(path))
    except (OSError, ValueError) as error:
        pe_info = {"error": str(error)}

    try:
        signature_info = verify_signature(str(path))
    except Exception as error:
        signature_info = {"error": str(error)}

    ANALYSIS_CACHE[cache_key] = {
        "file_state": file_state,
        "pe": pe_info,
        "signature": signature_info,
    }

    return pe_info, signature_info



def inspect_processes():
    detected = []

    for process in psutil.process_iter(
        ["pid", "name", "exe", "cmdline"]
    ):
        try:
            info = process.info

            name = info.get("name") or ""
            executable = info.get("exe") or ""

            if not name or not executable:
                continue

            process_type = classify_process(name, executable)

            if process_type not in TARGET_TYPES:
                continue

            path = Path(executable)

            if not path.is_file():
                continue


            pe_info, signature_info = analyze_file_cached(path)

            process_data = {
                "pid": info.get("pid"),
                "name": name,
                "type": process_type,
                "executable": str(path),
                "command_line": info.get("cmdline") or [],
                "pe": pe_info,
                "signature": signature_info,
            }

            process_data["trust"] = analyze_trust(process_data)

            process_data["path_check"] = verify_path(
                process_type,
                str(path),
            )

            detected.append(process_data)

