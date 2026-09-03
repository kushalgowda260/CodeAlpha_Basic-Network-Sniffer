# CodeAlpha Basic Network Sniffer

A Python-based network sniffer developed as part of the CodeAlpha Cyber Security Internship.

## Project Overview

This project captures and analyzes network packets using Python and Scapy. It displays useful information about network traffic and helps understand how different protocols communicate.

## Features

- Captures live network packets
- Supports IPv4 and IPv6
- Detects TCP and UDP traffic
- Detects ICMPv4 and ICMPv6 traffic
- Displays source and destination IP addresses
- Displays source and destination ports
- Identifies common network services
- Supports TCP, UDP, ICMP, and all-traffic filtering
- Provides packet statistics
- Saves captured traffic to a log file
- Detects possible port scanning using a basic rule
- Saves security alerts to a separate log file

## Technologies Used

- Python
- Scapy
- Networking
- Cybersecurity

## Requirements

- Python 3.x
- Scapy

Install Scapy using:

```bash
pip install scapy
How to Run

Clone or download this repository.

Open the project folder in VS Code or PowerShell.

Install Scapy:

pip install scapy

Run the program:

python sniffer.py

Choose a packet filter:

1. TCP
2. UDP
3. ICMP
4. All

Select the required option and allow the program to capture network traffic.

Press Ctrl+C to stop the sniffer.

Windows

On Windows, run PowerShell or the VS Code terminal as Administrator if packet capture requires elevated permissions.

Output

The program displays:

Source IP
Destination IP
Protocol
Source Port
Destination Port
Service

Example:

PACKET
=======================================================
Source IP       : 192.168.1.10
Destination IP  : 142.250.183.14
Protocol        : TCP
Source Port     : 52341
Destination Port: 443
Service         : HTTPS
=======================================================

The program also generates:

network_log.txt
security_alerts.txt
Port Scan Detection

The project includes a basic rule-based mechanism to identify possible port-scanning activity.

If a single source IP contacts 10 or more different destination ports, the program generates a possible port-scan alert.

This is a basic detection mechanism and does not confirm that an attack has occurred.

Project Purpose

The purpose of this project is to gain practical understanding of:

Network packet capture
Network protocols
IP addresses
TCP and UDP ports
Packet analysis
Basic security monitoring
Rule-based threat detection
CodeAlpha Internship

Developed as part of the CodeAlpha Cyber Security Internship – Task 1: Basic Network Sniffer.

The CodeAlpha task requires building a Python program to capture network traffic packets and analyze captured packets to understand their structure, content, data flow, and basic protocols.

