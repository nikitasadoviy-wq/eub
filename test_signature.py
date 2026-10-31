
from core.signature_verifier import verify_signature

FILES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
]

for file_path in FILES:
    print(f"\nChecking: {file_path}")
    print(verify_signature(file_path))
