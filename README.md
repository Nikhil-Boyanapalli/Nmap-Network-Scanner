# Network Scanner

A comprehensive network scanning and vulnerability assessment tool with a graphical user interface, built using Python and PyQt6. This application combines the power of Nmap for network discovery and service detection with an intuitive interface for security professionals and network administrators.

## Features

- 🔍 Automatic network detection
- 🚀 Multiple scan types:
  - Host Discovery
  - Quick Service Scan
  - Full Service Scan
- 📊 Real-time scan progress viewing
- 📝 Detailed reporting including:
  - Device information
  - Open ports
  - Running services
  - Vulnerabilities
  - Security recommendations
- 🎨 User-friendly graphical interface
- 📋 Export and save scan results

## Prerequisites

- Python 3.8 or higher
- Nmap 7.0 or higher

### Installing Nmap

#### Windows
1. Download Nmap from [nmap.org](https://nmap.org/download.html)
2. Run the installer with administrator privileges
3. Ensure Nmap is added to your system PATH

#### Linux
```bash
sudo apt-get update
sudo apt-get install nmap
```

#### macOS
```bash
brew install nmap
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Nikhil-Boyanapalli/Nmap-Network-Scanner.git
cd Nmap-Network-Scanner
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python main.py
```

2. Select the desired scan type from the dropdown menu
3. Click "Start Scan" to begin network scanning
4. View real-time progress in the application window
5. Access detailed reports through the "View Reports" button

## Project Structure
Nmap-Network-Scanner/
├── main.py # Main application entry point
├── scanner.py # Network scanning functionality
├── report_viewer.py # Report viewing interface
├── requirements.txt # Python dependencies
└── README.md # Project documentation

## Security Considerations

- This tool should only be used on networks you have permission to scan
- Running network scans may trigger security systems
- Some scan types require administrator/root privileges
- Always follow your organization's security policies

## Limitations

- Scan speed depends on network size and scan type
- Some features require administrator/root privileges
- Results accuracy depends on target network conditions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Nmap for network scanning capabilities
- PyQt6 for the graphical interface
- Python community for various libraries

## Disclaimer

This tool is for educational and professional use only. Users are responsible for ensuring they have appropriate permissions before scanning any networks.

## Creating Windows Executable

You can create a Windows executable file for easier distribution and use. Follow these steps:

1. Install PyInstaller:
```bash
pip install pyinstaller
```

2. Create the executable:

Basic version:
```bash
pyinstaller --onefile --windowed --name "Network Scanner" main.py
```

With custom icon:
```bash
pyinstaller --onefile --windowed --icon=icon.ico --name "Network Scanner" main.py
```

Options explained:
- `--onefile`: Creates a single executable file
- `--windowed`: Prevents console window from appearing
- `--icon`: Adds a custom icon (optional)
- `--name`: Sets the executable name

The executable will be created in the `dist` folder as "Network Scanner.exe"

**Note:** 
- The executable may take longer to start compared to running the Python script
- Nmap must still be installed on the target system
- The final executable size will be larger than the Python scripts due to included dependencies