# VulnScan: Automated Penetration Testing Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)  [![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/) 
## Description

VulnScan is a Python-based automated penetration testing tool designed to streamline the process of identifying vulnerabilities in target systems. It integrates various popular open-source security tools, automating scans for common weaknesses and generating comprehensive reports in text, HTML, and PDF formats. VulnScan aims to simplify penetration testing tasks and provide a consolidated view of potential security risks.

## Features

*   **Comprehensive Tool Integration:** Automates the execution of multiple penetration testing tools, including Nmap, Nikto, Gobuster, SQLMap, Searchsploit, Hydra, John the Ripper, and Aircrack-ng.
*   **Concurrent Scanning:** Leverages `concurrent.futures.ThreadPoolExecutor` for faster results by running scans concurrently.
*   **Flexible Reporting:** Generates reports in text, HTML, and PDF formats, providing options for different levels of detail and presentation.
*   **Customizable Options:** Allows users to customize tool options via command-line arguments, providing flexibility for specific scanning needs.
*   **Detailed Logging:** Includes detailed logging for debugging and analysis, enabling tracking of scan progress and identification of potential issues.
*   **Improved Output Parsing:** Employs regular expressions for improved output parsing, ensuring accurate extraction of findings from various tools.
*   **Robust Error Handling:** Implements robust error handling and argument validation to prevent unexpected issues and ensure reliable execution.
*   **Cross-Platform Compatibility:** Designed for cross-platform compatibility, allowing usage on various operating systems.

## Installation

1.  **Clone the Repository:**

    ```bash
    git clone https://github.com/GriffynPython/VulnScan.git
    cd VulnScan
    ```

2.  **Create a Virtual Environment (Recommended):**

    ```bash
    python3 -m venv .venv  # Create a virtual environment
    source .venv/bin/activate  # Activate the environment (Linux/macOS)
    .venv\Scripts\activate  # Activate the environment (Windows)
    ```

3.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt  # Install from requirements.txt (preferred)
    # OR
    pip install beautifulsoup4 reportlab colorama python-nmap
    ```

4.  **Install Penetration Testing Tools:**

    You will need to install the following tools separately.  Ensure they are in your system's `PATH`:

    *   **Nmap:** [https://nmap.org/](https://nmap.org/)
    *   **Nikto:** [https://cirt.net/Nikto2/](https://cirt.net/Nikto2/)
    *   **Gobuster:** [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster)
    *   **SQLMap:** [http://sqlmap.org/](http://sqlmap.org/)
    *   **Searchsploit:** (Usually included with Metasploit or can be installed separately)
    *   **Hydra:** [https://thehackerschoice.com/hydra/](https://thehackerschoice.com/hydra/)
    *   **John the Ripper:** [https://www.openwall.com/john/](https://www.openwall.com/john/)
    *   **Aircrack-ng:** [https://www.aircrack-ng.org/](https://www.aircrack-ng.org/)

## Usage

```bash
python vulnscan.py -i <target_ip> --nmap --nikto --gobuster --sqlmap --searchsploit apache --hydra --john hashes.txt --aircrack capture.cap -w wordlist.txt --report-format html --threads 8
