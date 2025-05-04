# security-automation-project
# Automated Intrusion Detection and Response System Using Suricata

## Project Objective

To build a real-time, automated intrusion detection and response system using Suricata, Python, and EveBox on Ubuntu.

## Features

- Suricata-based packet inspection
- Real-time alert parsing using Python
- Automated blocking of malicious IPs using `iptables`
- Web-based dashboard using EveBox

## Setup Instructions

### Prerequisites

- Ubuntu 20.04+
- Python 3.x
- Suricata
- EveBox

### Installation

```bash
sudo apt install suricata
wget https://evebox.org/files/evebox-0.20.3-amd64.deb
sudo dpkg -i evebox-0.20.3-amd64.deb
pip install -r requirements.txt
```
