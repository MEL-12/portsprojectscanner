# Port Scanner

A command-line network port scanner built with Python and nmap that detects open ports and displays service and version information on any target host.


## Project Description

This project is a lightweight CLI-based network port scanner that uses Python and the nmap library to scan a target host for open ports. It displays a color-coded table showing each port's state (open, filtered, or closed), the service running on it, and the version information. It supports TCP and UDP scanning, custom port ranges, adjustable timeouts, and optional output saving to a text file.


## Steps Taken to Complete the Project

### 1. Set Up the Project Environment
- Created the project folder `portsprojectscanner`
- Created four project files at once: `scanner.py`, `requirements.txt`, `README.md`, and `.gitignore`
- Created and activated a Python virtual environment:
```bash
  python3 -m venv venv
  source venv/bin/activate
```

### 2. Installed Dependencies
- Added `python-nmap` and `colorama` to `requirements.txt`
- Installed dependencies using:
```bash
  pip install -r requirements.txt
```
- Installed nmap on the system:
```bash
  sudo apt install nmap
```

### 3. Built the Scanner
- Written in `scanner.py` with the following features:
  - **Argument parsing** — accepts target, port range, timeout, UDP flag, and output file via CLI
  - **Host resolution** — resolves hostnames to IP addresses
  - **Nmap scan** — runs service and version detection using `python-nmap`
  - **Result parsing** — extracts port, protocol, state, service name, and version info
  - **Color-coded output** — green for open, yellow for filtered, red for closed ports
  - **Save to file** — optionally saves results to a text file stripping ANSI color codes

### 4. Tested the Scanner
- Tested against `scanme.nmap.org`, a safe and legal test target provided by the nmap project:
```bash
  python scanner.py scanme.nmap.org
```

### 5. Pushed to GitHub
- Initialised a Git repository and made the first commit
- Set up `.gitignore` to exclude `venv/`, `__pycache__/`, and other unnecessary files
- Pushed the project to GitHub:
```bash
  git add .
  git commit -m "feat: initial port scanner with nmap service detection"
  git push -u origin main
```


## Requirements

- Python 3.8+
- nmap installed on your OS:
  - **macOS:** `brew install nmap`
  - **Linux:** `sudo apt install nmap`
  - **Windows:** Download from [nmap.org](https://nmap.org/download.html)


## Setup

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/portsprojectscanner.git
cd portsprojectscanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate      # macOS/Linux
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```


## Usage

```bash
python scanner.py <target> [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p`, `--ports` | Port range or list (e.g. `1-1024` or `80,443`) | `1-1024` |
| `-t`, `--timeout` | Timeout per port in seconds | `1.0` |
| `--udp` | Enable UDP scan (requires sudo/admin) | off |
| `-o`, `--output` | Save results to a text file | — |


## Examples

```bash
# Scan default ports on a test host
python scanner.py scanme.nmap.org

# Full port scan
python scanner.py 192.168.1.1 -p 1-65535

# Specific ports with output saved
python scanner.py 10.0.0.1 -p 80,443,8080 -o results.txt

# UDP scan (Linux/macOS — run with sudo)
sudo python scanner.py 192.168.1.1 --udp
```

## Legal Notice

> Only scan systems you own or have **explicit written permission** to scan.
> Unauthorized port scanning may be illegal in your jurisdiction.