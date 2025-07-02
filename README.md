
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

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="500" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/InventoryDemo.gif?raw=true"/> 
</div>


## Directory Structure

```
├── data
│   ├── auth
│   │   └── logins.json
│   └── inventory
│       ├── SERVER.json
│       └── SOC1.json
├── logs
├── ssl
│   ├── cert.pem
│   └── key.pem
├── static
│   ├── css
│   │   ├── all.min.css
│   │   └── styles.css
│   ├── favicon.png
│   ├── js
│   │   └── chart.js
│   ├── logo.svg
│   └── mlogo.svg
├── templates
│   ├── base.html
│   ├── dashboard.html
│   ├── error.html
│   ├── login.html
│   ├── machine_details.html
│   ├── painel.html
│   └── search.html
├── TODO.md
└── utils
    ├── get_data.py
    └── man_users.py

```

## Prerequisites

- Python 3.8+
- Operational Wazuh environment
- Dependencies: `Flask`, `bcrypt`, `python-dotenv`

## Environment Configuration (`.env`)

```ini
# Configurações de segurança
SECRET_KEY=suachavesupersecreta_altere_esta_chave!
INVENTORY_DIR=data/inventory
AUTH_FILE=data/auth/logins.json

# Configurações de rede
HOST=0.0.0.0
PORT=8000
DEBUG=False

# Configurações de HTTPS
USE_HTTPS=True
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem

# Proteção contra força bruta
MAX_LOGIN_ATTEMPTS=3
LOGIN_BLOCK_TIME=60

# Permitir apenas IPs de uma faixa específica
ALLOWED_IP_RANGES =192.168.0.0/16

#ARQUIVO DE IPs BLOQUEADOS
BLOCKED_IPS_FILE = logs/blocked_ips.json 

WAZUH_PROTOCOL=https
WAZUH_HOST=192.168.56.210
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=ma?Pt3XvLxQzpU8.dYhxzV?pT
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
   Here you need to configure wazuh-wui credentials.
   You can retrieve the credentials from the .tar with the command:
   ```bash
   sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O
   ```
4. Set credentials on utils/get_data.py

5. Create TLS/SSL Cert:
  ```bash
  openssl req -x509 -newkey rsa:4096 -nodes -out ssl/cert.pem -keyout ssl/key.pem -days 365 
  ```
6. Start the web application:
   ```bash
   python app.py
   ```
7. Default Login and Password:
   ```bash
   Login: admin
   Password: Meuadmin123
   ```
OBS: É possivel criar e remover usuãrios pelo "./utils/man_users.py" 

## Monitoring & Maintenance

- **Recommended Routines**  
  - Daily execution of the collector  
  - Periodic audit of the user file (e.g., `users.json` or similar)  
  - Regular renewal of SSL certificates  

## Future Improvements

- **Docker**  
  - Deploy with docker image
  - Automation with docker compose (dockerfile)  
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
- **Export Relatory**  
  - Export to PDF or CSV File
  - Integration with another tool
