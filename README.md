# EUB — Edge Ecosystem Blocker

**EUB (Edge Ecosystem Blocker)** is a Windows monitoring and analysis tool designed to identify and inspect Microsoft Edge-related processes, services, installers, and scheduled tasks.

The project focuses on process discovery, executable analysis, digital signature verification, and configurable monitoring.

> **Development status:** Early development — v0.1.0

## Features

- **Process detection** — identifies known Microsoft Edge-related processes.
- **PE analysis** — inspects executable metadata, architecture, sections, imports, and version information.
- **SHA-256 hashing** — calculates executable file hashes.
- **Authenticode verification** — checks executable digital signatures and publisher information.
- **Process classification** — categorizes detected processes by type.
- **Analysis cache** — avoids repeatedly analyzing identical executable files.
- **Service inspection** — checks selected Edge-related Windows services.
- **Scheduled task inspection** — discovers Edge-related scheduled tasks.
- **Configurable monitoring** — supports adjustable scan intervals and monitoring settings.
- **Logging** — records detection and analysis results.

## Project Structure

```text
EUB/
├── main.py
├── core/
│   ├── allowlist.py
│   ├── installer_guard.py
│   ├── pe_analyzer.py
│   ├── policy_manager.py
│   ├── process_classifier.py
│   ├── process_guard.py
│   ├── service_guard.py
│   ├── signature_verifier.py
│   └── task_guard.py
├── config/
│   └── settings.json
├── requirements.txt
├── test_pe.py
├── test_signature.py
├── .gitignore
└── README.md
```

## Requirements

- Windows 10 or Windows 11
- Python 3.13 or newer
- Git
- Required Python packages listed in `requirements.txt`

## Installation

Clone the repository:

```powershell
git clone https://github.com/nikitasadoviy-wq/EUB.git
cd EUB
```

Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

## Usage

Start EUB:

```powershell
py main.py
```

Monitoring settings are stored in:

```text
config/settings.json
```

## Safety and Design

EUB is currently focused on **read-only monitoring and analysis**.

- No automatic process termination.
- No automatic service disabling.
- No automatic scheduled task deletion.
- No automatic registry modifications.
- WebView2 compatibility is an important design consideration.

Detection and trust assessment are separate concepts. A valid digital signature does not automatically mean that a process should be allowed or blocked.

## Development Roadmap

- [x] Initial process discovery
- [x] Process classification
- [x] PE executable analysis
- [x] SHA-256 calculation
- [x] Authenticode signature verification
- [x] Basic analysis caching
- [x] Windows service inspection
- [x] Scheduled task inspection
- [ ] Process Trust Analyzer
- [ ] Improved WebView2 allowlist validation
- [ ] Extended Edge ecosystem discovery
- [ ] Improved logging and reporting
- [ ] Automated tests
- [ ] GUI

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
