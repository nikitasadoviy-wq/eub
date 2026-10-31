import json
from core.pe_analyzer import analyze_pe

target = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

result = analyze_pe(target)

print(json.dumps(result, indent=4, ensure_ascii=False))