# CodeAlpha-CyberSecurity-Task-1
# Network Sniffer using Python 🐍

## 🔍 Overview
This is a simple Python-based network sniffer tool built using the `scapy` library. It captures and analyzes packets on the local network interface and prints key details like source IP, destination IP, protocol, ports, and raw payload.

This project was completed as part of the **Cyber Security Internship at CodeAlpha**.

---

## ⚙️ Features
- Captures network traffic using Scapy.
- Prints:
  - Source and destination IP addresses.
  - Protocol (TCP, UDP, ICMP).
  - Source and destination ports.
  - Raw payload (first 100 bytes).
- Real-time output in the terminal.

---

## 🛠️ Requirements
- Python 3.6+
- `scapy` library
- `Npcap` (for Windows users)

## Install dependencies:
```bash
pip install scapy
```
## ▶️ How to Run
Open your terminal as Administrator (on Windows).

Navigate to the project directory.

## Run the script:
```bash
python sniffer.py
```
For better results, make sure you are connected to an active network (Wi-Fi or Ethernet), and try browsing websites during capture

## ⚠️ Legal Disclaimer
This tool was developed for educational purposes only.
It was tested in a controlled environment on my own system and network.
I do not encourage or support any form of unauthorized network monitoring or packet sniffing

## 📸 Sample Output:
```bash
--- New Packet ---
Time: 2025-06-25 12:45:10
Source IP: 192.168.1.101
Destination IP: 142.250.184.206
Protocol: TCP
Source Port: 50038
Destination Port: 443
Payload:
b'\x16\x03\x01...'
```
## 📁 Files
sniffer.py – main packet sniffer script

## 💼 Author
Osman Hassbo – Cyber Security Intern @ CodeAlpha
LinkedIn: https://www.linkedin.com/in/osman-hassabalrsoul-594419224/
Email: osmanhasspo@gmail.com
X(Twitter): https://x.com/osman_hassabo?t=U1yOEacEQWrLUiPs8JHypw&s=09
Facebook: https://www.facebook.com/share/1CH1FcEJja/
