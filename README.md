
<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/Inventory.gif?raw=true"/> 
</div>

# Machine Inventory System with WAZUH

This document describes the architecture, components, and operation of a machine inventory system for corporate environments using Wazuh. The solution integrates data collection via script, processing, and web-based visualization, emphasizing security and ease of operation. The architecture is modular, scalable, and follows best practices for data protection.

## Overview

The system inventories devices with Wazuh agents in two main layers:

- **Data Collector**: Connects to the Wazuh API, gathers detailed information from each agent (hardware, OS, network, open ports), and stores JSON files named by hostname.
- **Web Application (Flask)**: Provides a secure interface for viewing and analyzing collected data, featuring statistical dashboards, machine panels, advanced search, and authentication.

**Operation Flow**:
```
Wazuh Collector → JSON Data → Flask App → Dashboard / Panel
```

## Core Components

### 1. Collector Module

Interacts with the Wazuh API in these steps:

- **JWT Authentication**: Obtain an access token for authenticated requests.
- **Agent Listing**: Retrieve monitored devices.
- **Inventory Collection**: Extract hardware specs, OS details, network info, and open ports per agent.
- **Status Classification**: Mark devices as “Online” if active in the last 30 days; otherwise, “Offline.”
- **Local Storage**: Write structured JSON files named after each hostname.

### 2. Web Application (Flask)

Accessible via browser, with:

- **Secure Authentication**  
  - Passwords hashed with bcrypt  
  - IP blocking after configurable failed attempts  
  - Sessions expire after a set time (e.g., 30 minutes)
- **Statistical Dashboard**  
  - Charts for OS distribution, CPU types, RAM usage
- **Machine Panel**  
  - Full device list with advanced filtering
- **Advanced Search**  
  - Filter by IP, OS, hardware, or other criteria
- **Machine Details**  
  - Detailed view of collected data per host

## Directory Structure Example

```
├── data
│   ├── auth
│   │   └── logins.json
│   └── inventory
│       ├── SERVER.json
│       └── SOC1.json
├── README.md
├── ssl
│   ├── cert.pem
│   └── key.pem
├── static
│   ├── css
│   │   ├── all.min.css
│   │   └── styles.css
│   ├── favicon.png
│   ├── js
│   │   └── chart.js
│   ├── logo.svg
│   └── mlogo.svg
├── templates
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   ├── machine_details.html
│   ├── panel.html
│   └── search.html
└── utils
    ├── get_data.py
    └── man_users.py
```

## Prerequisites

- Python 3.8+
- Operational Wazuh environment
- Dependencies: `Flask`, `bcrypt`, `requests`, `python-dotenv`

## Environment Configuration (`.env`)

```ini
# Security
SECRET_KEY=your_super_secret_key_here
INVENTORY_DIR=data/inventory
AUTH_FILE=data/auth/logins.json

# Network
HOST=0.0.0.0
PORT=8000
DEBUG=False

# HTTPS
USE_HTTPS=True
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem

# Brute-force Protection
MAX_LOGIN_ATTEMPTS=3
LOGIN_BLOCK_TIME=300  # seconds
```

## Installation & Execution

1. Clone the repository and configure `.env` as above.
   ```bash
   https://github.com/Maarckz/Inventory.git
   ```
2. Install dependencies:
   ```bash
   pip install flask bcrypt requests python-dotenv
   ```
3. Run the collector (manually or via a button in the UI):
   ```bash
   python3 utils/get_data.py
   ```
4. Start the web application:
   ```bash
   python app.py
   ```
5. Default Login and Password:
   ```bash
   Login: admin
   Password: Meuadmin123
   ```
## Monitoring & Maintenance

- **Recommended Routines**  
  - Daily execution of the collector  
  - Periodic audit of the user file (e.g., `users.json` or similar)  
  - Regular renewal of SSL certificates  
- **Logging**  
  - Flask App: errors, access logs, failed login attempts  
  - Collector: processed agents and failures  

## Future Improvements

- **Collector**  
  - Externalize credentials via environment variables  
  - Parallel execution for scale  
  - Customizable SSL verification  
- **Web Application**  
  - Caching for static data  
  - Report export (PDF/CSV)  
  - REST API for external integrations  
- **Security**  
  - Multi-factor authentication (MFA)  
  - Encryption of JSON inventory files  
  - Detailed access auditing  
