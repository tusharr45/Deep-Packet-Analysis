# Deep Packet Inspection (DPI) Network Traffic Analyzer

A Python-based Deep Packet Inspection (DPI) Network Traffic Analyzer that captures live network packets, analyzes traffic patterns, detects DNS domains, and provides real-time monitoring through a GUI dashboard.

## Overview

This project demonstrates how network monitoring and basic intrusion detection systems work by inspecting packets, identifying protocols, tracking flows, and generating alerts for suspicious domains.

The tool supports both:
- Live network traffic capture
- Offline PCAP file analysis

## Features

### Packet Analysis
- Live packet capture using PyShark
- PCAP file analysis
- TCP / UDP / DNS protocol detection
- Packet logging to CSV

### Network Monitoring
- DNS query monitoring (detect visited websites)
- Flow tracking (top communicating IPs)
- Protocol statistics
- Traffic visualization

### Security Features
- Rule-based domain detection
- Alert system for blocked domains
- Suspicious traffic alerts
- Security event logging

### GUI Dashboard
- Real-time packet monitoring
- Protocol statistics display
- Network flow table
- Protocol distribution charts
- CSV export functionality

## Project Structure
