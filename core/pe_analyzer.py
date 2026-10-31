
import hashlib
import pefile
from pathlib import Path


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def analyze_pe(file_path):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(file_path)

    result = {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": calculate_sha256(path),
        "is_pe": False
    }

    try:
        pe = pefile.PE(str(path), fast_load=False)

        result.update({
            "is_pe": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "pe_type": (
                "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B
                else "PE32"
            ),
            "sections": [
                {
                    "name": section.Name.rstrip(b"\0").decode(
                        "ascii", errors="replace"
                    ),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData
                }
                for section in pe.sections
            ],
            "imports": sorted({
                entry.dll.decode("utf-8", errors="replace")
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            }),
            "version_info": {}
        })

        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for table in entry.StringTable:
                            for key, value in table.entries.items():
                                result["version_info"][
                                    key.decode(errors="replace")
                                ] = value.decode(errors="replace")

        pe.close()

    except pefile.PEFormatError as error:
        result["error"] = str(error)

    return result
