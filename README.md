# Port Scanner

A Python-based port scanning tool with a graphical user interface (GUI) designed to perform TCP and UDP scans, detect open ports, grab service banners, identify potential vulnerabilities, and provide security analysis. The tool supports single IP, domain, or CIDR range scanning and includes OS detection via ICMP ping TTL values.

## Features
- **GUI Interface**: Built with CustomTkinter for an intuitive user experience, supporting English and Arabic languages.
- **Scan Types**:
  - TCP Full Connect Scan with banner grabbing.
  - TCP SYN Scan (requires root privileges).
  - UDP Scan.
- **Predefined Port Ranges**: Options for common ports, web servers, FTP, or custom ranges.
- **Vulnerability Detection**:
  - Checks for high-risk ports (e.g., FTP, Telnet, SMB).
  - Matches service banners against a static vulnerability database.
  - Queries the NVD API for known vulnerabilities based on banners (requires API key).
- **OS Detection**: Estimates the operating system using ICMP ping TTL values.
- **Security Analysis**: Summarizes total hosts, open ports, high-risk ports, vulnerabilities, and provides recommendations.
- **Reporting**: Save results as TXT or PDF files.
- **Concurrency**: Supports up to 100 concurrent tasks for efficient scanning.
- **Cancel Scan**: Ability to cancel ongoing scans.
- **NVD API Integration**: Configurable API key for real-time vulnerability checks.

## Requirements
- Python 3.9+
- Required Python packages:
  - `customtkinter`
  - `scapy`
  - `reportlab`
  - `requests`
- Optional: NVD API key for vulnerability checks (configure in `settings.json`).
- Root/admin privileges for TCP SYN scans and OS detection (raw sockets).

## Installation
1. Clone or download the repository.
2. Install dependencies:
   ```bash
   pip install customtkinter scapy reportlab requests
   ```
3. (Optional) Obtain an NVD API key from [NVD](https://nvd.nist.gov/developers/request-an-api-key) and add it to `settings.json`:
   ```json
   {
       "nvd_api_key": "your-api-key-here"
   }
   ```
4. Run the GUI:
   ```bash
   python scanner_gui.py
   ```

## Usage
1. **Launch the GUI**:
   ```bash
   python scanner_gui.py
   ```
2. **Input Fields**:
   - **Target**: Enter an IP address, domain, or CIDR range (e.g., `192.168.1.0/24`).
   - **Protocol**: Select TCP, UDP, or Both.
   - **Scan Type**: Choose Full Connect or SYN Scan (SYN requires root).
   - **Ports**: Select predefined ranges (e.g., Common Ports) or enter custom start/end ports.
   - **Timeout**: Set the scan timeout (default: 0.5 seconds).
   - **NVD API Key**: Enter and save your NVD API key for vulnerability checks.
3. **Start Scan**: Click "Start Scan" to begin. Progress is shown in the progress bar.
4. **View Results**: Results and security analysis are displayed in the textboxes.
5. **Save Report**: Save results as a TXT or PDF file.
6. **New Scan**: Click "New Scan" to reset the GUI.
7. **Cancel Scan**: Stop an ongoing scan.
8. **Switch Language**: Toggle between English and Arabic.

## CLI Usage
The port scanner can also be run from the command line:
```bash
python port_scanner.py
```
- Follow the prompts to enter the target, protocol, port range, scan type, and timeout.
- Results and security analysis are printed to the console.

## Building Executable
To create a standalone executable using PyInstaller:
1. Ensure PyInstaller is installed:
   ```bash
   pip install pyinstaller
   ```
2. Use the provided `PortScanner.spec` file:
   ```bash
   pyinstaller PortScanner.spec
   ```
3. The executable will be in the `dist/PortScanner` directory.

## Files
- `scanner_gui.py`: Main GUI application.
- `port_scanner.py`: Core scanning logic (TCP, UDP, OS detection).
- `analyzer.py`: Analyzes scan results for vulnerabilities and recommendations.
- `vulnerabilities.py`: Defines high-risk ports and static vulnerability database.
- `config.py`: Configuration settings (timeouts, GUI sizes, language support).
- `settings.json`: Stores the NVD API key.
- `PortScanner.spec`: PyInstaller configuration for building the executable.

## Notes
- **Root Privileges**: SYN scans and OS detection require raw socket access, which needs root/admin privileges (`sudo` on Linux).
- **NVD API**: Without an API key, vulnerability checks are limited to the static database in `vulnerabilities.py`.
- **Performance**: Scanning large CIDR ranges or many ports may take time. Adjust `MAX_CONCURRENT` in `config.py` for performance tuning.
- **Banner Grabbing**: Limited to 1024 bytes and 100 characters after cleaning to prevent overflow.
- **UDP Scans**: May report `open|filtered` due to UDP's stateless nature.

## Limitations
- SYN scans are not supported without root privileges.
- UDP scans may have false positives due to firewall configurations.
- OS detection is basic and relies on TTL, which may be unreliable.
- NVD API queries are cached for 1 hour to avoid rate limits.
- The static vulnerability database (`VULN_DB`) is limited and should be expanded for production use.

## License
This project is licensed under the MIT License.

## Disclaimer
This tool is for educational and authorized testing purposes only. Unauthorized scanning of networks or systems is illegal. Use responsibly and with permission.