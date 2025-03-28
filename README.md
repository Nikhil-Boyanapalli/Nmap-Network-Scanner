# Network Security Scanner

A comprehensive network security scanning tool with GUI interface that combines Nmap scanning capabilities with OpenVAS vulnerability assessment.

## Features

- Network Discovery & Scanning
  - Quick Scan
  - Intensive Scan
  - Stealth Scan
  - UDP Scan
- Service and OS Detection
- Vulnerability Assessment (OpenVAS Integration)
- Professional Report Generation (PDF/HTML)

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure you have Nmap installed on your system:
   - Windows: Download and install from https://nmap.org/download.html
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

4. (Optional) Set up OpenVAS for vulnerability scanning:
   - Follow the OpenVAS installation guide for your platform
   - Configure the OpenVAS credentials in the `.env` file

## Usage

Run the application:
```bash
python main.py
```

## Configuration

Create a `.env` file in the project root with the following variables:
```
OPENVAS_HOST=your_openvas_host
OPENVAS_USER=your_username
OPENVAS_PASSWORD=your_password
```

## License

MIT License 